require('dotenv').config();
require('./bootstrap'); // creates shop.db and its tables if they don't exist yet
const prisma = require('./prisma');
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const { fromBuffer: fileTypeFromBuffer } = require('file-type');
const { doubleCsrf } = require('csrf-csrf');
const { recordFailure, isLocked, clearAttempts } = require('./views/middleware/loginlimiter');

const app = express();
const SHOP_NAME = 'Tewabu Shifon';
const WHATSAPP_NUMBER = '251932174589';
const TELEGRAM_USERNAME = 'we4543';

// ---------- secrets: pull from environment, never hardcode ----------
const OWNER_USERNAME = process.env.OWNER_USERNAME;
const OWNER_PASSWORD = process.env.OWNER_PASSWORD; // only used for first-run seed
const SESSION_SECRET = process.env.SESSION_SECRET;
const CSRF_SECRET = process.env.CSRF_SECRET;

if (!SESSION_SECRET || !CSRF_SECRET) {
  throw new Error('SESSION_SECRET and CSRF_SECRET must be set in your .env file');
}

// Cloth code shown to customers, for example TS-0007
const CODE_PREFIX = 'TS';
app.locals.codeOf = (id) => CODE_PREFIX + '-' + String(id).padStart(4, '0');

// ---------- uploads: accept into memory first, verify real content, then write to disk ----------
const ALLOWED_TYPES = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/webp': '.webp',
};
const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({
  storage: multer.memoryStorage(),
  
  fileFilter: (req, file, cb) => cb(null, !!ALLOWED_TYPES[file.mimetype]),
  limits: { fileSize: 5 * 1024 * 1024 },
});

// Deletes picture files from the uploads folder
function removeFiles(names) {
  names.forEach((n) => fs.unlink(path.join(UPLOAD_DIR, n), () => {}));
}

async function validateAndSaveImages(files) {
  const saved = [];
  try {
    for (const file of files) {
      const type = await fileTypeFromBuffer(file.buffer);
      if (!type || !ALLOWED_TYPES[type.mime]) {
        throw new Error('One of the files is not a valid image.');
      }
      const filename = crypto.randomBytes(8).toString('hex') + ALLOWED_TYPES[type.mime];
      fs.writeFileSync(path.join(UPLOAD_DIR, filename), file.buffer);
      saved.push(filename);
    }
    return saved;
  } catch (err) {
    removeFiles(saved);
    throw err;
  }
}

app.set('view engine', 'ejs');
app.locals.shopName = SHOP_NAME;
app.locals.whatsappNumber = WHATSAPP_NUMBER;
app.locals.telegramUsername = TELEGRAM_USERNAME;

// ---------- security headers ----------
// Helmet sets HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy
// and a Content-Security-Policy with sane defaults. The CSP below is
// customized for what this site actually loads: the Tailwind CDN script,
// Google Fonts, and the small inline <script> blocks in a couple of views
// (the delete modal/toast, the product gallery). Tailwind's CDN script and
// those inline blocks both require 'unsafe-inline' — there is no nonce
// support for the Tailwind Play CDN, so this is the practical middle ground
// rather than a fully locked-down CSP. Everything else (fonts, images,
// scripts, frames) is restricted to this site or the two CDNs it actually
// uses.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'self'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));

// Helmet doesn't set Permissions-Policy on its own — this disables browser
// features the site never uses, which is what a security scan checks for.
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=()');
  next();
});

app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use('/uploads', express.static('uploads'));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 },
}));

// ---------- CSRF protection ----------
const { generateToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => CSRF_SECRET,
  cookieName: process.env.NODE_ENV === 'production' ? '__Host-csrf' : 'csrf',
  cookieOptions: {
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
  },
  // Our forms send the token as a hidden field named "_csrf" in the POST
  // body, not as an x-csrf-token header (the library's default), so we
  // have to point it at the right place.
  getTokenFromRequest: (req) => req.body && req.body._csrf,
});

// Make a fresh token available to every admin view (forms read it as csrfToken)
app.use('/admin', (req, res, next) => {
  try {
    res.locals.csrfToken = generateToken(req, res);
  } catch (err) {
    // The visitor's browser has a leftover CSRF cookie that no longer
    // validates (e.g. left over from an old CSRF_SECRET, or a previous
    // library version during testing). Rather than crash the request,
    // just force a brand new token/cookie to be issued.
    res.locals.csrfToken = generateToken(req, res, true);
  }
  next();
});

function requireOwner(req, res, next) {
  if (req.session.owner) return next();
  res.redirect('/admin/login');
}

// Every cloth, with its first picture (by position, then id) as the "cover"
async function getProductsWithCover() {
  const products = await prisma.products.findMany({
    orderBy: { id: 'desc' },
    include: {
      images: { orderBy: [{ position: 'asc' }, { id: 'asc' }], take: 1 },
    },
  });
  return products.map((p) => ({ ...p, image: p.images[0] ? p.images[0].filename : '' }));
}

// ---------- customers: no login needed ----------
app.get('/', async (req, res) => {
  const products = await getProductsWithCover();
  res.render('home', { products, shopName: SHOP_NAME });
});

app.get('/product/:id', async (req, res) => {
  const id = Number(req.params.id);
  const item = await prisma.products.findUnique({ where: { id } });
  if (!item) return res.status(404).send('Cloth not found');

  const images = await prisma.product_images.findMany({
    where: { product_id: id },
    orderBy: [{ position: 'asc' }, { id: 'asc' }],
  });

  const code = app.locals.codeOf(item.id);
  const link = req.protocol + '://' + req.get('host') + '/product/' + item.id;
  const message = 'Hello, I would like to order: ' + item.name +
    ' (Code: ' + code + ', ' + item.price + ' ETB). ' + link;

  res.render('product', {
    item,
    images,
    shopName: SHOP_NAME,
    whatsappLink: 'https://wa.me/' + WHATSAPP_NUMBER + '?text=' + encodeURIComponent(message),
    telegramLink: 'https://t.me/' + TELEGRAM_USERNAME,
  });
});

// ---------- login and logout ----------
app.get('/admin/login', (req, res) => {
  res.render('login', { error: null });
});

// Login form is posted before a session/CSRF token exists for this visitor,
// so it's intentionally left off doubleCsrfProtection. Brute-force is instead
// mitigated by the rate limiter below.
app.post('/admin/login', async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const key = `${req.ip}:${username}`;

  if (isLocked(key)) {
    return res.status(429).render('login', {
      error: 'Too many attempts. Try again in a few minutes.',
    });
  }

  const owner = await prisma.owner.findUnique({ where: { id: 1 } });
  const ok = owner
    && username === String(owner.username).toLowerCase()
    && await bcrypt.compare(password, owner.password_hash);

  if (!ok) {
    recordFailure(key);
    return res.status(401).render('login', { error: 'Wrong username or password.' });
  }

  clearAttempts(key);

  req.session.regenerate((err) => {
    if (err) return res.status(500).render('login', { error: 'Something went wrong, try again.' });
    req.session.owner = true;
    res.redirect('/admin');
  });
});

app.post('/admin/logout', requireOwner, doubleCsrfProtection, (req, res) => {
  req.session.destroy(() => res.redirect('/admin/login'));
});

// ---------- owner: list ----------
app.get('/admin', requireOwner, async (req, res) => {
  const products = await getProductsWithCover();
  res.render('admin', { products, deletedName: req.query.deleted || null });
});

// ---------- owner: add cloth ----------
app.get('/admin/new', requireOwner, (req, res) => {
  res.render('form', {
    heading: 'Add cloth',
    action: '/admin/new',
    error: null,
    item: { name: '', price: '', description: '' },
    images: [],
  });
});

// multer must run before doubleCsrfProtection here: this form is
// multipart/form-data (because of the file input), and express.urlencoded()
// does not parse multipart bodies — only multer does. If CSRF ran first,
// req.body would still be undefined and the _csrf check would crash.
app.post('/admin/new', requireOwner, upload.array('images', 8), doubleCsrfProtection, async (req, res) => {
  const files = req.files || [];
  const name = String(req.body.name || '').trim();
  const description = String(req.body.description || '').trim();
  const price = Number(req.body.price);

  if (!name || !(price > 0)) {
    return res.status(400).render('form', {
      heading: 'Add cloth',
      action: '/admin/new',
      error: 'Enter a name and a price greater than 0. Please choose the pictures again.',
      item: { name, price: req.body.price, description },
      images: [],
    });
  }

  let filenames;
  try {
    filenames = await validateAndSaveImages(files);
  } catch (err) {
    return res.status(400).render('form', {
      heading: 'Add cloth',
      action: '/admin/new',
      error: 'One of the files was not a valid image. Please choose the pictures again.',
      item: { name, price: req.body.price, description },
      images: [],
    });
  }

  const created = await prisma.products.create({ data: { name, description, price } });

  if (filenames.length) {
    await prisma.product_images.createMany({
      data: filenames.map((filename, i) => ({ product_id: created.id, filename, position: i })),
    });
  }

  res.redirect('/admin');
});

// ---------- owner: edit cloth ----------
app.get('/admin/edit/:id', requireOwner, async (req, res) => {
  const id = Number(req.params.id);
  const item = await prisma.products.findUnique({ where: { id } });
  if (!item) return res.redirect('/admin');

  const images = await prisma.product_images.findMany({
    where: { product_id: id },
    orderBy: [{ position: 'asc' }, { id: 'asc' }],
  });
  res.render('form', { heading: 'Edit cloth', action: '/admin/edit/' + id, error: null, item, images });
});

app.post('/admin/edit/:id', requireOwner, upload.array('images', 8), doubleCsrfProtection, async (req, res) => {
  const id = Number(req.params.id);
  const files = req.files || [];
  const old = await prisma.products.findUnique({ where: { id } });
  if (!old) {
    return res.redirect('/admin');
  }

  const images = await prisma.product_images.findMany({
    where: { product_id: id },
    orderBy: [{ position: 'asc' }, { id: 'asc' }],
  });
  const name = String(req.body.name || '').trim();
  const description = String(req.body.description || '').trim();
  const price = Number(req.body.price);
  const remove = [].concat(req.body.remove || []).map(Number);
  const keepCount = images.filter((im) => !remove.includes(im.id)).length;

  let error = null;
  if (!name || !(price > 0)) error = 'Enter a name and a price greater than 0.';
  else if (keepCount + files.length > 8) error = 'A cloth can have at most 8 pictures.';

  if (error) {
    return res.status(400).render('form', {
      heading: 'Edit cloth',
      action: '/admin/edit/' + id,
      error,
      item: { id, name, price: req.body.price, description },
      images,
    });
  }

  let filenames;
  try {
    filenames = await validateAndSaveImages(files);
  } catch (err) {
    return res.status(400).render('form', {
      heading: 'Edit cloth',
      action: '/admin/edit/' + id,
      error: 'One of the files was not a valid image. Please choose the pictures again.',
      item: { id, name, price: req.body.price, description },
      images,
    });
  }

  await prisma.products.update({ where: { id }, data: { name, description, price } });

  const removed = images.filter((im) => remove.includes(im.id));
  if (removed.length) {
    await prisma.product_images.deleteMany({ where: { id: { in: removed.map((im) => im.id) } } });
    removeFiles(removed.map((im) => im.filename));
  }

  let position = images.length ? Math.max(...images.map((im) => im.position)) + 1 : 0;
  if (filenames.length) {
    await prisma.product_images.createMany({
      data: filenames.map((filename, i) => ({ product_id: id, filename, position: position + i })),
    });
  }

  res.redirect('/admin');
});

// ---------- owner: delete cloth ----------
app.post('/admin/delete/:id', requireOwner, doubleCsrfProtection, async (req, res) => {
  const id = Number(req.params.id);
  const product = await prisma.products.findUnique({ where: { id } });
  const images = await prisma.product_images.findMany({ where: { product_id: id } });
  await prisma.product_images.deleteMany({ where: { product_id: id } });
  await prisma.products.delete({ where: { id } });
  removeFiles(images.map((im) => im.filename));
  res.redirect('/admin?deleted=' + encodeURIComponent(product ? product.name : 'Item'));
});

// ---------- owner: change username / password ----------
app.get('/admin/account', requireOwner, async (req, res) => {
  const owner = await prisma.owner.findUnique({ where: { id: 1 } });
  res.render('account', { error: null, message: null, username: owner.username });
});

app.post('/admin/account', requireOwner, doubleCsrfProtection, async (req, res) => {
  const owner = await prisma.owner.findUnique({ where: { id: 1 } });
  const current = String(req.body.current || '');
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const again = String(req.body.again || '');

  const fail = (error) => res.status(400).render('account', { error, message: null, username });

  if (!(await bcrypt.compare(current, owner.password_hash))) return fail('Your current password is wrong.');
  if (!username) return fail('Enter a username.');

  let hash = owner.password_hash;
  if (password) {
    if (password.length < 8) return fail('The new password must be at least 8 characters.');
    if (password !== again) return fail('The new passwords do not match.');
    hash = bcrypt.hashSync(password, 12);
  }

  await prisma.owner.update({ where: { id: 1 }, data: { username, password_hash: hash } });
  res.render('account', { error: null, message: 'Saved. Use your new details the next time you log in.', username });
});

// ---------- error handler: must be registered last, before listen() ----------
// Catches CSRF failures (and anything else passed to next(err)) so visitors
// see a normal page instead of a raw stack trace, and so a bad request can
// never crash the whole server process.
app.use((err, req, res, next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    console.warn('CSRF check failed for', req.method, req.originalUrl);
    return res.status(403).send(
      'Your session expired or the form was out of date. Please go back, refresh the page, and try again.'
    );
  }
  console.error(err);
  res.status(500).send('Something went wrong. Please try again.');
});

// ---------- startup: seed the owner row on first run, then start listening ----------
async function ensureOwner() {
  const existing = await prisma.owner.findUnique({ where: { id: 1 } });
  if (!existing) {
    if (!OWNER_USERNAME || !OWNER_PASSWORD) {
      throw new Error('Set OWNER_USERNAME and OWNER_PASSWORD in .env for first-time setup');
    }
    await prisma.owner.create({
      data: { id: 1, username: OWNER_USERNAME, password_hash: bcrypt.hashSync(OWNER_PASSWORD, 12) },
    });
  }
}

ensureOwner()
  .then(() => {
    app.listen(3000, () => console.log('Open http://localhost:3000'));
  })
  .catch((err) => {
    console.error('Startup failed:', err);
    process.exit(1);
  });