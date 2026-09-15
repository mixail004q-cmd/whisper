require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');
const helmet = require('helmet');
const path = require('path');
const { pool, initDB } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '';
const MAX_POSTS = parseInt(process.env.MAX_POSTS_PER_USER || '500', 10);
const MAX_COMMENTS = parseInt(process.env.MAX_COMMENTS_PER_USER || '2000', 10);
const TURNSTILE_ENABLED = process.env.TURNSTILE_ENABLED === 'true';

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('JWT_SECRET слишком короткий. Нужно >= 32 символов.');
  process.exit(1);
}

app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", 'https://challenges.cloudflare.com'],
      frameSrc: ["'self'", 'https://challenges.cloudflare.com'],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https://challenges.cloudflare.com']
    }
  },
  crossOriginEmbedderPolicy: false
}));

app.use((req, res, next) => {
  if (ALLOWED_ORIGIN && req.headers.origin && req.headers.origin !== ALLOWED_ORIGIN) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  next();
});

app.use(express.json({ limit: '64kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));

// ============ УТИЛИТЫ ============
function clean(str, max = 3000) {
  if (typeof str !== 'string') return '';
  return sanitizeHtml(str.trim().slice(0, max), { allowedTags: [], allowedAttributes: {} });
}

function isValidLogin(s) {
  return typeof s === 'string' && /^[A-Za-z0-9_\-]{3,20}$/.test(s);
}

function isValidPassword(s) {
  return typeof s === 'string' && s.length >= 8 && s.length <= 128;
}

async function logAudit(req, action, targetType, targetId, details = {}) {
  try {
    await pool.query(
      `INSERT INTO audit_log (actor_id, actor_login, action, target_type, target_id, details, ip)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        req.user ? req.user.id : null,
        req.user ? req.user.login : null,
        action,
        targetType || null,
        targetId || null,
        JSON.stringify(details),
        (req.ip || '').slice(0, 60)
      ]
    );
  } catch (e) { console.error('audit log error:', e.message); }
}

function setSession(res, user) {
  const token = jwt.sign(
    { id: user.id, login: user.login, role: user.role, tv: user.token_version || 0 },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.cookie('token', token, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

function auth(required = true, roles = null) {
  return async (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
      if (!required) return next();
      return res.status(401).json({ error: 'Не авторизован' });
    }
    try {
      const payload = jwt.verify(token, JWT_SECRET);

      // Проверяем актуальность токена и бан
      const u = await pool.query(
        'SELECT id, login, role, token_version, is_banned, banned_until FROM users WHERE id = $1',
        [payload.id]
      );
      if (u.rowCount === 0) return res.status(401).json({ error: 'Аккаунт не найден' });
      const user = u.rows[0];

      if (user.is_banned) {
        const until = user.banned_until ? new Date(user.banned_until) : null;
        if (!until || until > new Date()) {
          return res.status(403).json({ error: 'Аккаунт заблокирован' });
        }
        await pool.query('UPDATE users SET is_banned=FALSE, banned_reason=NULL, banned_until=NULL WHERE id=$1', [user.id]);
      }

      if ((payload.tv || 0) !== (user.token_version || 0)) {
        return res.status(401).json({ error: 'Сессия устарела, войди заново' });
      }

      req.user = { id: user.id, login: user.login, role: user.role };
      if (roles && !roles.includes(user.role)) {
        return res.status(403).json({ error: 'Недостаточно прав' });
      }
      next();
    } catch {
      if (!required) return next();
      return res.status(401).json({ error: 'Сессия истекла' });
    }
  };
}

async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_ENABLED) return true;
  if (!token) return false;
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: process.env.TURNSTILE_SECRET_KEY,
        response: token,
        remoteip: ip
      })
    });
    const d = await r.json();
    return d.success === true;
  } catch { return false; }
}

// ============ RATE LIMITS ============
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 8, message: { error: 'Слишком много попыток. Жди 15 минут.' } });
const registerLimiter = rateLimit({ windowMs: 60*60*1000, max: 3, message: { error: 'Слишком много регистраций.' } });
const postLimiter = rateLimit({ windowMs: 60*1000, max: 6, message: { error: 'Слишком часто. Подожди минуту.' } });
const commentLimiter = rateLimit({ windowMs: 60*1000, max: 20, message: { error: 'Слишком часто комментируешь.' } });
const ticketLimiter = rateLimit({ windowMs: 60*60*1000, max: 3, message: { error: 'Слишком много тикетов.' } });
const readLimiter = rateLimit({ windowMs: 60*1000, max: 120, message: { error: 'Слишком много запросов.' } });
const sensitiveLimiter = rateLimit({ windowMs: 60*60*1000, max: 5, message: { error: 'Слишком часто.' } });

// ============ HEALTH ============
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', ts: Date.now() });
  } catch { res.status(500).json({ status: 'db_error' }); }
});

// ============ AUTH ============
app.post('/api/register', registerLimiter, async (req, res) => {
  const login = (req.body.login || '').trim();
  const password = req.body.password || '';
  const email = (req.body.email || '').trim().toLowerCase() || null;
  const turnstileToken = req.body.turnstileToken || '';

  if (!isValidLogin(login)) return res.status(400).json({ error: 'Логин: 3-20 символов, буквы/цифры/_/-' });
  if (!isValidPassword(password)) return res.status(400).json({ error: 'Пароль: 8-128 символов' });
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Неверный email' });

  const turnstileOk = await verifyTurnstile(turnstileToken, req.ip);
  if (!turnstileOk) return res.status(400).json({ error: 'Проверка капчи не пройдена' });

  try {
    const exists = await pool.query('SELECT 1 FROM users WHERE LOWER(login)=LOWER($1)', [login]);
    if (exists.rowCount > 0) return res.status(400).json({ error: 'Логин занят' });

    const hash = await bcrypt.hash(password, 12);
    const r = await pool.query(
      'INSERT INTO users (login, password_hash, role, email) VALUES ($1,$2,$3,$4) RETURNING id, login, role, token_version',
      [login, hash, 'user', email]
    );
    const user = r.rows[0];
    setSession(res, user);
    res.json({ user: { login: user.login, role: user.role } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  const login = (req.body.login || '').trim();
  const password = req.body.password || '';

  try {
    const r = await pool.query('SELECT * FROM users WHERE LOWER(login)=LOWER($1)', [login]);
    if (r.rowCount === 0) return res.status(400).json({ error: 'Неверный логин или пароль' });
    const user = r.rows[0];

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: 'Неверный логин или пароль' });

    if (user.is_banned) {
      const until = user.banned_until ? new Date(user.banned_until) : null;
      if (!until || until > new Date()) {
        return res.status(403).json({ error: 'Аккаунт заблокирован' + (user.banned_reason ? ': ' + user.banned_reason : '') });
      }
      await pool.query('UPDATE users SET is_banned=FALSE, banned_reason=NULL, banned_until=NULL WHERE id=$1', [user.id]);
    }

    setSession(res, user);
    await logAudit({ user: { id: user.id, login: user.login }, ip: req.ip }, 'login', 'user', user.id);
    res.json({ user: { login: user.login, role: user.role } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', auth(false), async (req, res) => {
  if (!req.user) return res.json({ user: null });
  const u = await pool.query('SELECT login, role, email, created_at FROM users WHERE id=$1', [req.user.id]);
  if (u.rowCount === 0) return res.json({ user: null });
  res.json({ user: { login: u.rows[0].login, role: u.rows[0].role, email: u.rows[0].email } });
});

// ============ СМЕНА ПАРОЛЯ ============
app.post('/api/change-password', auth(true), sensitiveLimiter, async (req, res) => {
  const oldPass = req.body.oldPassword || '';
  const newPass = req.body.newPassword || '';

  if (!isValidPassword(newPass)) return res.status(400).json({ error: 'Новый пароль: 8-128 символов' });

  const r = await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.user.id]);
  const ok = await bcrypt.compare(oldPass, r.rows[0].password_hash);
  if (!ok) return res.status(400).json({ error: 'Неверный текущий пароль' });

  const hash = await bcrypt.hash(newPass, 12);
  await pool.query('UPDATE users SET password_hash=$1, token_version=token_version+1 WHERE id=$2', [hash, req.user.id]);
  await logAudit(req, 'change_password', 'user', req.user.id);

  res.clearCookie('token');
  res.json({ ok: true, message: 'Пароль изменён. Войди заново.' });
});

// ============ ЭКСПОРТ ДАННЫХ ============
app.get('/api/export', auth(true), sensitiveLimiter, async (req, res) => {
  const posts = await pool.query(
    `SELECT id, type, body, is_anon, allow_comments, created_at, edited_at FROM posts WHERE user_id=$1 ORDER BY created_at DESC`,
    [req.user.id]
  );
  const comments = await pool.query(
    `SELECT id, post_id, body, created_at, edited_at FROM comments WHERE user_id=$1 ORDER BY created_at DESC`,
    [req.user.id]
  );
  const tickets = await pool.query(
    `SELECT id, subject, reason, status, created_at FROM tickets WHERE user_id=$1 ORDER BY created_at DESC`,
    [req.user.id]
  );
  await logAudit(req, 'export_data', 'user', req.user.id);
  res.json({ user: { login: req.user.login }, posts: posts.rows, comments: comments.rows, tickets: tickets.rows });
});

// ============ УДАЛЕНИЕ АККАУНТА ============
app.delete('/api/account', auth(true), sensitiveLimiter, async (req, res) => {
  const password = req.body.password || '';
  const r = await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.user.id]);
  const ok = await bcrypt.compare(password, r.rows[0].password_hash);
  if (!ok) return res.status(400).json({ error: 'Неверный пароль' });

  if (req.user.role === 'main_admin') return res.status(403).json({ error: 'Главного админа нельзя удалить' });

  await logAudit(req, 'delete_account', 'user', req.user.id);
  await pool.query('DELETE FROM users WHERE id=$1', [req.user.id]);
  res.clearCookie('token');
  res.json({ ok: true });
});

// ============ POSTS ============
app.get('/api/posts', readLimiter, async (req, res) => {
  const { type } = req.query;
  let sql = `
    SELECT p.id, p.type, p.body, p.is_anon, p.author_name, p.allow_comments,
           p.created_at, p.edited_at,
           (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comments_count
    FROM posts p
    WHERE p.is_hidden = FALSE`;
  const params = [];
  if (type === 'secret' || type === 'story') {
    sql += ' AND p.type = $1';
    params.push(type);
  }
  sql += ' ORDER BY p.created_at DESC LIMIT 200';

  const r = await pool.query(sql, params);
  res.json({ posts: r.rows });
});

app.get('/api/posts/:id', readLimiter, auth(false), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const r = await pool.query(
    `SELECT p.* FROM posts p WHERE p.id=$1 AND p.is_hidden=FALSE`, [id]
  );
  if (r.rowCount === 0) return res.status(404).json({ error: 'Не найдено' });
  const post = r.rows[0];

  const c = await pool.query(
    `SELECT id, user_id, body, author_name, author_role, pinned, created_at, edited_at
     FROM comments WHERE post_id=$1
     ORDER BY pinned DESC, created_at ASC`, [id]
  );
  res.json({ post, comments: c.rows });
});

app.post('/api/posts', auth(true), postLimiter, async (req, res) => {
  const type = req.body.type === 'story' ? 'story' : 'secret';
  const body = clean(req.body.body, 3000);
  const isAnon = req.body.isAnon !== false;
  const allowComments = req.body.allowComments !== false;

  if (body.length < 2) return res.status(400).json({ error: 'Слишком короткий текст' });

  const cnt = await pool.query('SELECT COUNT(*)::int AS c FROM posts WHERE user_id=$1', [req.user.id]);
  if (cnt.rows[0].c >= MAX_POSTS) return res.status(400).json({ error: `Лимит: ${MAX_POSTS} публикаций` });

  const authorName = isAnon ? 'Аноним' : req.user.login;
  const r = await pool.query(
    `INSERT INTO posts (user_id, type, body, is_anon, author_name, allow_comments)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
    [req.user.id, type, body, isAnon, authorName, allowComments]
  );
  res.json({ ok: true, id: r.rows[0].id });
});

app.put('/api/posts/:id', auth(true), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const body = clean(req.body.body, 3000);
  const isAnon = req.body.isAnon !== false;
  const allowComments = req.body.allowComments !== false;
  if (body.length < 2) return res.status(400).json({ error: 'Слишком короткий текст' });

  const o = await pool.query('SELECT user_id FROM posts WHERE id=$1', [id]);
  if (o.rowCount === 0) return res.status(404).json({ error: 'Не найдено' });

  const isOwner = o.rows[0].user_id === req.user.id;
  const isAdmin = ['main_admin','admin'].includes(req.user.role);
  if (!isOwner && !isAdmin) return res.status(403).json({ error: 'Нет прав' });

  const authorName = isAnon ? 'Аноним' : req.user.login;
  await pool.query(
    `UPDATE posts SET body=$1, is_anon=$2, author_name=$3, allow_comments=$4, edited_at=NOW() WHERE id=$5`,
    [body, isAnon, authorName, allowComments, id]
  );
  await logAudit(req, 'edit_post', 'post', id);
  res.json({ ok: true });
});

app.delete('/api/posts/:id', auth(true), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const o = await pool.query('SELECT user_id FROM posts WHERE id=$1', [id]);
  if (o.rowCount === 0) return res.status(404).json({ error: 'Не найдено' });

  const isOwner = o.rows[0].user_id === req.user.id;
  const isAdmin = ['main_admin','admin'].includes(req.user.role);
  if (!isOwner && !isAdmin) return res.status(403).json({ error: 'Нет прав' });

  await pool.query('DELETE FROM posts WHERE id=$1', [id]);
  await logAudit(req, 'delete_post', 'post', id);
  res.json({ ok: true });
});

// Скрыть пост (админ)
app.post('/api/posts/:id/hide', auth(true, ['main_admin','admin']), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  await pool.query('UPDATE posts SET is_hidden = NOT is_hidden WHERE id=$1', [id]);
  await logAudit(req, 'toggle_hide_post', 'post', id);
  res.json({ ok: true });
});

// ============ COMMENTS ============
app.post('/api/posts/:id/comments', auth(true), commentLimiter, async (req, res) => {
  const postId = parseInt(req.params.id, 10);
  const body = clean(req.body.body, 500);
  if (body.length < 1) return res.status(400).json({ error: 'Пусто' });

  const post = await pool.query('SELECT allow_comments FROM posts WHERE id=$1 AND is_hidden=FALSE', [postId]);
  if (post.rowCount === 0) return res.status(404).json({ error: 'Пост не найден' });
  if (!post.rows[0].allow_comments) return res.status(403).json({ error: 'Комментарии отключены' });

  const cnt = await pool.query('SELECT COUNT(*)::int AS c FROM comments WHERE user_id=$1', [req.user.id]);
  if (cnt.rows[0].c >= MAX_COMMENTS) return res.status(400).json({ error: `Лимит: ${MAX_COMMENTS} комментариев` });

  const r = await pool.query(
    `INSERT INTO comments (post_id, user_id, body, author_name, author_role)
     VALUES ($1,$2,$3,$4,$5) RETURNING id`,
    [postId, req.user.id, body, req.user.login, req.user.role]
  );
  res.json({ ok: true, id: r.rows[0].id });
});

app.put('/api/comments/:id', auth(true), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const body = clean(req.body.body, 500);
  if (body.length < 1) return res.status(400).json({ error: 'Пусто' });

  const c = await pool.query('SELECT user_id FROM comments WHERE id=$1', [id]);
  if (c.rowCount === 0) return res.status(404).json({ error: 'Не найдено' });
  if (c.rows[0].user_id !== req.user.id) return res.status(403).json({ error: 'Нет прав' });

  await pool.query('UPDATE comments SET body=$1, edited_at=NOW() WHERE id=$2', [body, id]);
  res.json({ ok: true });
});

app.delete('/api/comments/:id', auth(true), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const c = await pool.query(
    `SELECT cm.user_id, p.user_id AS post_owner FROM comments cm
     JOIN posts p ON p.id = cm.post_id WHERE cm.id=$1`, [id]
  );
  if (c.rowCount === 0) return res.status(404).json({ error: 'Не найдено' });

  const isCommentOwner = c.rows[0].user_id === req.user.id;
  const isPostOwner = c.rows[0].post_owner === req.user.id;
  const isAdmin = ['main_admin','admin'].includes(req.user.role);
  if (!isCommentOwner && !isPostOwner && !isAdmin) return res.status(403).json({ error: 'Нет прав' });

  await pool.query('DELETE FROM comments WHERE id=$1', [id]);
  await logAudit(req, 'delete_comment', 'comment', id);
  res.json({ ok: true });
});

app.post('/api/comments/:id/pin', auth(true), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const c = await pool.query(
    `SELECT cm.pinned, p.user_id AS post_owner FROM comments cm
     JOIN posts p ON p.id = cm.post_id WHERE cm.id=$1`, [id]
  );
  if (c.rowCount === 0) return res.status(404).json({ error: 'Не найдено' });

  const isPostOwner = c.rows[0].post_owner === req.user.id;
  const isAdmin = ['main_admin','admin'].includes(req.user.role);
  if (!isPostOwner && !isAdmin) return res.status(403).json({ error: 'Нет прав' });

  await pool.query('UPDATE comments SET pinned = NOT pinned WHERE id=$1', [id]);
  await logAudit(req, 'toggle_pin_comment', 'comment', id);
  res.json({ ok: true });
});

// ============ TICKETS ============
app.post('/api/tickets', auth(true), ticketLimiter, async (req, res) => {
  const subject = clean(req.body.subject, 120);
  const reason = clean(req.body.reason, 2000);
  const priority = ['low','normal','high'].includes(req.body.priority) ? req.body.priority : 'normal';
  if (subject.length < 3) return res.status(400).json({ error: 'Тема минимум 3 символа' });
  if (reason.length < 5) return res.status(400).json({ error: 'Опиши подробнее' });

  const r = await pool.query(
    'INSERT INTO tickets (user_id, subject, reason, priority) VALUES ($1,$2,$3,$4) RETURNING id',
    [req.user.id, subject, reason, priority]
  );
  const tid = r.rows[0].id;
  await pool.query(
    `INSERT INTO ticket_messages (ticket_id, user_id, author_name, author_role, body)
     VALUES ($1,$2,$3,$4,$5)`,
    [tid, req.user.id, req.user.login, req.user.role, reason]
  );
  res.json({ ok: true, id: tid });
});

app.get('/api/tickets/my', auth(true), async (req, res) => {
  const r = await pool.query(
    `SELECT t.*, (SELECT COUNT(*) FROM ticket_messages tm WHERE tm.ticket_id=t.id) AS messages_count
     FROM tickets t WHERE t.user_id=$1 ORDER BY t.updated_at DESC`,
    [req.user.id]
  );
  res.json({ tickets: r.rows });
});

app.get('/api/tickets', auth(true, ['main_admin','admin','support']), async (req, res) => {
  const status = req.query.status || 'open';
  const r = await pool.query(
    `SELECT t.*, u.login AS user_login,
     (SELECT COUNT(*) FROM ticket_messages tm WHERE tm.ticket_id=t.id) AS messages_count
     FROM tickets t LEFT JOIN users u ON u.id=t.user_id
     WHERE t.status=$1 ORDER BY t.priority DESC, t.updated_at DESC LIMIT 200`,
    [status]
  );
  res.json({ tickets: r.rows });
});

app.get('/api/tickets/:id', auth(true), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const t = await pool.query('SELECT * FROM tickets WHERE id=$1', [id]);
  if (t.rowCount === 0) return res.status(404).json({ error: 'Не найдено' });

  const ticket = t.rows[0];
  const isOwner = ticket.user_id === req.user.id;
  const isStaff = ['main_admin','admin','support'].includes(req.user.role);
  if (!isOwner && !isStaff) return res.status(403).json({ error: 'Нет прав' });

  const m = await pool.query(
    'SELECT * FROM ticket_messages WHERE ticket_id=$1 ORDER BY created_at ASC', [id]
  );
  res.json({ ticket, messages: m.rows });
});

app.post('/api/tickets/:id/messages', auth(true), commentLimiter, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const body = clean(req.body.body, 1000);
  if (body.length < 1) return res.status(400).json({ error: 'Пусто' });

  const t = await pool.query('SELECT * FROM tickets WHERE id=$1', [id]);
  if (t.rowCount === 0) return res.status(404).json({ error: 'Не найдено' });

  const ticket = t.rows[0];
  const isOwner = ticket.user_id === req.user.id;
  const isStaff = ['main_admin','admin','support'].includes(req.user.role);
  if (!isOwner && !isStaff) return res.status(403).json({ error: 'Нет прав' });

  await pool.query(
    `INSERT INTO ticket_messages (ticket_id, user_id, author_name, author_role, body)
     VALUES ($1,$2,$3,$4,$5)`,
    [id, req.user.id, req.user.login, req.user.role, body]
  );
  await pool.query('UPDATE tickets SET updated_at=NOW() WHERE id=$1', [id]);
  res.json({ ok: true });
});

app.put('/api/tickets/:id/status', auth(true, ['main_admin','admin','support']), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const status = ['open','closed'].includes(req.body.status) ? req.body.status : 'open';
  await pool.query('UPDATE tickets SET status=$1, updated_at=NOW() WHERE id=$2', [status, id]);
  await logAudit(req, 'ticket_status', 'ticket', id, { status });
  res.json({ ok: true });
});

app.get('/api/tickets/notify', auth(true, ['main_admin','admin','support']), async (req, res) => {
  const r = await pool.query(`SELECT COUNT(*)::int AS cnt FROM tickets WHERE status='open'`);
  res.json({ open: r.rows[0].cnt });
});

// ============ STAFF ============
app.get('/api/staff', auth(true, ['main_admin','admin']), async (req, res) => {
  const r = await pool.query(
    `SELECT id, login, role, is_banned, banned_reason, banned_until, created_at
     FROM users WHERE role IN ('main_admin','admin','support') ORDER BY created_at ASC`
  );
  res.json({ staff: r.rows });
});

app.post('/api/staff', auth(true, ['main_admin']), async (req, res) => {
  const login = (req.body.login || '').trim();
  const role = ['admin','support'].includes(req.body.role) ? req.body.role : null;
  if (!isValidLogin(login)) return res.status(400).json({ error: 'Неверный логин' });
  if (!role) return res.status(400).json({ error: 'Неверная роль' });

  const u = await pool.query('SELECT id, role FROM users WHERE LOWER(login)=LOWER($1)', [login]);
  if (u.rowCount === 0) return res.status(404).json({ error: 'Пользователь не найден' });
  if (u.rows[0].role === 'main_admin') return res.status(403).json({ error: 'Нельзя менять главного админа' });

  await pool.query('UPDATE users SET role=$1 WHERE id=$2', [role, u.rows[0].id]);
  await logAudit(req, 'assign_role', 'user', u.rows[0].id, { role });
  res.json({ ok: true });
});

app.delete('/api/staff/:login', auth(true, ['main_admin']), async (req, res) => {
  const login = req.params.login;
  const u = await pool.query('SELECT id, role FROM users WHERE LOWER(login)=LOWER($1)', [login]);
  if (u.rowCount === 0) return res.status(404).json({ error: 'Не найден' });
  if (u.rows[0].role === 'main_admin') return res.status(403).json({ error: 'Нельзя снять главного админа' });

  await pool.query('UPDATE users SET role=$1 WHERE id=$2', ['user', u.rows[0].id]);
  await logAudit(req, 'remove_role', 'user', u.rows[0].id);
  res.json({ ok: true });
});

// ============ BANS ============
app.post('/api/users/:login/ban', auth(true, ['main_admin','admin']), async (req, res) => {
  const login = req.params.login;
  const reason = clean(req.body.reason, 200);
  const days = parseInt(req.body.days || '7', 10);
  const until = days > 0 ? new Date(Date.now() + days * 86400000) : null;

  const u = await pool.query('SELECT id, role FROM users WHERE LOWER(login)=LOWER($1)', [login]);
  if (u.rowCount === 0) return res.status(404).json({ error: 'Не найден' });
  if (u.rows[0].role === 'main_admin') return res.status(403).json({ error: 'Нельзя забанить главного админа' });
  if (req.user.role === 'admin' && ['admin','support'].includes(u.rows[0].role)) {
    return res.status(403).json({ error: 'Админ не может банить персонал' });
  }

  await pool.query('UPDATE users SET is_banned=TRUE, banned_reason=$1, banned_until=$2 WHERE id=$3',
    [reason || 'Нарушение правил', until, u.rows[0].id]);
  await logAudit(req, 'ban_user', 'user', u.rows[0].id, { reason, days });
  res.json({ ok: true });
});

app.post('/api/users/:login/unban', auth(true, ['main_admin','admin']), async (req, res) => {
  const login = req.params.login;
  const u = await pool.query('SELECT id FROM users WHERE LOWER(login)=LOWER($1)', [login]);
  if (u.rowCount === 0) return res.status(404).json({ error: 'Не найден' });
  await pool.query('UPDATE users SET is_banned=FALSE, banned_reason=NULL, banned_until=NULL WHERE id=$1', [u.rows[0].id]);
  await logAudit(req, 'unban_user', 'user', u.rows[0].id);
  res.json({ ok: true });
});

// ============ AUDIT LOG ============
app.get('/api/audit', auth(true, ['main_admin','admin']), async (req, res) => {
  const r = await pool.query(
    `SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200`
  );
  res.json({ logs: r.rows });
});

// ============ МОДЕРАЦИЯ: список скрытых ============
app.get('/api/hidden-posts', auth(true, ['main_admin','admin']), async (req, res) => {
  const r = await pool.query(
    `SELECT p.*, u.login AS owner_login FROM posts p
     LEFT JOIN users u ON u.id=p.user_id
     WHERE p.is_hidden=TRUE ORDER BY p.created_at DESC LIMIT 200`
  );
  res.json({ posts: r.rows });
});

// ============ СТАРТ ============
(async () => {
  try {
    await initDB();

    const mainLogin = process.env.MAIN_ADMIN_LOGIN;
    const mainPass = process.env.MAIN_ADMIN_PASSWORD;
    if (mainLogin && mainPass) {
      const exists = await pool.query('SELECT id FROM users WHERE login=$1', [mainLogin]);
      if (exists.rowCount === 0) {
        const hash = await bcrypt.hash(mainPass, 12);
        await pool.query(
          'INSERT INTO users (login, password_hash, role) VALUES ($1,$2,$3)',
          [mainLogin, hash, 'main_admin']
        );
        console.log(`[init] главный админ "${mainLogin}" создан`);
      }
    }

    app.listen(PORT, () => console.log(`[+] Сервер на http://localhost:${PORT}`));
  } catch (e) {
    console.error('Ошибка запуска:', e);
    process.exit(1);
  }
})();