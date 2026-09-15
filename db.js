const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      login VARCHAR(32) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(16) NOT NULL DEFAULT 'user',
      email VARCHAR(120),
      token_version INTEGER DEFAULT 0,
      is_banned BOOLEAN DEFAULT FALSE,
      banned_reason TEXT,
      banned_until TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      type VARCHAR(16) NOT NULL CHECK (type IN ('secret','story')),
      body TEXT NOT NULL,
      is_anon BOOLEAN DEFAULT TRUE,
      author_name VARCHAR(64) NOT NULL,
      allow_comments BOOLEAN DEFAULT TRUE,
      is_hidden BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      edited_at TIMESTAMPTZ
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS comments (
      id SERIAL PRIMARY KEY,
      post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      body TEXT NOT NULL,
      author_name VARCHAR(64) NOT NULL,
      author_role VARCHAR(16) NOT NULL DEFAULT 'user',
      is_anon BOOLEAN DEFAULT FALSE,
      pinned BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      edited_at TIMESTAMPTZ
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tickets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      subject VARCHAR(120) NOT NULL,
      reason TEXT NOT NULL,
      priority VARCHAR(8) DEFAULT 'normal',
      status VARCHAR(16) DEFAULT 'open',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ticket_messages (
      id SERIAL PRIMARY KEY,
      ticket_id INTEGER REFERENCES tickets(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      author_name VARCHAR(64) NOT NULL,
      author_role VARCHAR(16) NOT NULL,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id SERIAL PRIMARY KEY,
      actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      actor_login VARCHAR(32),
      action VARCHAR(64) NOT NULL,
      target_type VARCHAR(32),
      target_id INTEGER,
      details JSONB,
      ip VARCHAR(64),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Индексы
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_posts_hidden ON posts(is_hidden);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_comments_user ON comments(user_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_tmsg_ticket ON ticket_messages(ticket_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);`);

  console.log('[db] схема готова');
}

module.exports = { pool, initDB };