// Ensures shop.db and its tables exist before Prisma connects. Prisma only
// reads an existing database - on a brand new disk (e.g. a fresh Render
// deploy) there is nothing for it to read unless something creates the
// tables first. This runs once, at startup, using Node's built-in SQLite
// module, then gets out of the way; every real query in the app goes
// through Prisma (see prisma.js), not through this file.
//
// It resolves the database file from the same DATABASE_URL that Prisma
// uses (in .env), so the two never point at different files.
const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const path = require('path');

const rawUrl = process.env.DATABASE_URL || 'file:../shop.db';
const relativePath = rawUrl.replace(/^file:/, '');
// Prisma resolves this path relative to prisma/schema.prisma, so we
// resolve it the same way here: relative to the prisma/ folder.
const dbPath = path.resolve(__dirname, 'prisma', relativePath);

fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const db = new DatabaseSync(dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    price REAL NOT NULL,
    image TEXT NOT NULL DEFAULT ''
  )
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS owner (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL
  )
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS product_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    position INTEGER NOT NULL DEFAULT 0
  )
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    visitor TEXT NOT NULL,
    day TEXT NOT NULL,
    path TEXT NOT NULL
  )
`);

db.close(); // Prisma opens its own connection right after this file runs