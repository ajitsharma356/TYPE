'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  pass_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
  balance_paise INTEGER NOT NULL DEFAULT 0 CHECK (balance_paise >= 0),
  upi_id TEXT,
  blocked INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS task_attempts (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  type TEXT NOT NULL,
  display TEXT NOT NULL,
  expected TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('issued','accepted','rejected','expired')),
  accuracy REAL,
  reward_paise INTEGER NOT NULL DEFAULT 0,
  issued_at INTEGER NOT NULL,
  submitted_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_tasks_user ON task_attempts(user_id, status, submitted_at);
CREATE TABLE IF NOT EXISTS payouts (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  amount_paise INTEGER NOT NULL CHECK (amount_paise > 0),
  upi_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','paid','rejected')),
  note TEXT,
  created_at INTEGER NOT NULL,
  reviewed_at INTEGER,
  reviewed_by INTEGER REFERENCES users(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_pending_payout ON payouts(user_id) WHERE status = 'pending';
CREATE TABLE IF NOT EXISTS inquiries (
  id INTEGER PRIMARY KEY,
  company TEXT NOT NULL,
  email TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
`;

function createDb(file = process.env.DB_PATH || path.join(__dirname, 'data', 'taskwork.db')) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  if (file !== ':memory:') db.exec('PRAGMA journal_mode = WAL;');
  db.exec(SCHEMA);
  return db;
}

function tx(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

module.exports = { createDb, tx };
