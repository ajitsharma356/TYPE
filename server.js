'use strict';
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const { createDb, tx } = require('./db');
const sec = require('./lib/security');
const T = require('./lib/tasks');

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const TASK_TTL_MS = 30 * 60 * 1000;
const MIN_PAYOUT_PAISE = 30000;
const DAILY_LIMIT = 200;
const INVALID_LOGIN = 'Invalid email or password';
const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function createApp(opts = {}) {
  const db = opts.db || createDb();
  const secureCookies = opts.secureCookies ?? process.env.NODE_ENV === 'production';
  const COOKIE = secureCookies ? '__Host-tw_session' : 'tw_session';
  const limits = { loginIp: 20, loginEmail: 5, signup: 10, taskStart: 120, payout: 10, inquiry: 5, ...opts.limits };
  const rl = {
    loginIp: new sec.RateLimiter(limits.loginIp, 15 * 60e3),
    loginEmail: new sec.RateLimiter(limits.loginEmail, 15 * 60e3),
    signup: new sec.RateLimiter(limits.signup, 60 * 60e3),
    taskStart: new sec.RateLimiter(limits.taskStart, 60e3),
    payout: new sec.RateLimiter(limits.payout, 60 * 60e3),
    inquiry: new sec.RateLimiter(limits.inquiry, 60 * 60e3),
  };

  const app = express();
  app.disable('x-powered-by');
  const trustProxy = opts.trustProxy ?? process.env.TRUST_PROXY;
  if (trustProxy) app.set('trust proxy', /^\d+$/.test(String(trustProxy)) ? Number(trustProxy) : trustProxy);

  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        ...(secureCookies ? { upgradeInsecureRequests: [] } : {}),
      },
    },
    strictTransportSecurity: secureCookies,
  }));
  app.use((req, res, next) => {
    res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    next();
  });

  // ---- API middleware ----
  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (!MUTATING.has(req.method)) return next();
    // JSON-only + same-origin blocks classic form-based CSRF, including login CSRF.
    if (!req.is('application/json')) return res.status(415).json({ error: 'Content-Type must be application/json' });
    const origin = req.get('origin');
    if (origin) {
      let host = null;
      try { host = new URL(origin).host; } catch { /* "null" or malformed origin */ }
      // Compare host only; req.protocol is wrong behind a TLS-terminating proxy without trust proxy.
      if (host !== req.get('host')) return res.status(403).json({ error: 'Cross-origin request blocked' });
    }
    next();
  });
  app.use('/api', express.json({ limit: '10kb', strict: true }));

  const sessionQuery = db.prepare(`
    SELECT s.token_hash, s.csrf, s.expires_at, u.id, u.name, u.email, u.role, u.balance_paise, u.upi_id, u.blocked
    FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`);
  app.use('/api', (req, res, next) => {
    const token = sec.parseCookies(req.headers.cookie)[COOKIE];
    if (token && token.length <= 100) {
      const row = sessionQuery.get(sec.sha256(token));
      if (row && row.expires_at > Date.now() && !row.blocked) req.user = row;
      else if (row) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(row.token_hash);
    }
    // Public inquiry form is unprivileged; it stays protected by the JSON + Origin checks above.
    if (MUTATING.has(req.method) && req.user && req.path !== '/inquiries' && !sec.safeEqual(req.get('x-csrf-token') || '', req.user.csrf)) {
      return res.status(403).json({ error: 'Invalid CSRF token. Refresh the page and try again.' });
    }
    next();
  });

  const bad = (res, error) => res.status(400).json({ error });
  const tooMany = (res) => res.status(429).json({ error: 'Too many requests. Please wait and try again.' });
  const requireAuth = (req, res, next) => (req.user ? next() : res.status(401).json({ error: 'Please sign in' }));
  const requireAdmin = (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Please sign in' });
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
    next();
  };
  const idParam = (v) => {
    const n = Number(v);
    return /^\d{1,15}$/.test(String(v)) && n > 0 ? n : null;
  };

  function createSession(res, userId) {
    const token = sec.randomToken();
    const now = Date.now();
    db.prepare('INSERT INTO sessions (token_hash, user_id, csrf, expires_at, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(sec.sha256(token), userId, sec.randomToken(), now + SESSION_TTL_MS, now);
    res.setHeader('Set-Cookie', sec.serializeCookie(COOKIE, token, { maxAge: SESSION_TTL_MS / 1000, secure: secureCookies }));
  }
  const clearCookie = (res) => res.setHeader('Set-Cookie', sec.serializeCookie(COOKIE, '', { maxAge: 0, secure: secureCookies }));

  const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role, balance: u.balance_paise, upiId: u.upi_id });

  // ---- Auth ----
  app.post('/api/signup', async (req, res) => {
    if (!rl.signup.hit(req.ip)) return tooMany(res);
    const name = sec.cleanName(req.body?.name);
    const email = sec.cleanEmail(req.body?.email);
    const password = sec.cleanPassword(req.body?.password);
    if (!name) return bad(res, 'Name must be 2-60 letters');
    if (!email) return bad(res, 'Enter a valid email address');
    if (!password) return bad(res, 'Password must be 8-128 characters');
    const hash = await sec.hashPassword(password);
    let id;
    try {
      id = Number(db.prepare('INSERT INTO users (name, email, pass_hash, created_at) VALUES (?, ?, ?, ?)').run(name, email, hash, Date.now()).lastInsertRowid);
    } catch (err) {
      if (/UNIQUE/.test(err.message)) return res.status(409).json({ error: 'This email is already registered' });
      throw err;
    }
    if (req.user) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(req.user.token_hash);
    createSession(res, id);
    res.status(201).json({ ok: true });
  });

  app.post('/api/login', async (req, res) => {
    const email = sec.cleanEmail(req.body?.email);
    const password = typeof req.body?.password === 'string' && req.body.password.length <= 128 ? req.body.password : null;
    if (!rl.loginIp.hit(req.ip) || (email && !rl.loginEmail.hit(email))) return tooMany(res);
    if (!email || !password) return res.status(401).json({ error: INVALID_LOGIN });
    const u = db.prepare('SELECT id, pass_hash, blocked FROM users WHERE email = ?').get(email);
    const ok = await sec.verifyPassword(password, u ? u.pass_hash : await sec.dummyHash());
    if (!u || !ok) return res.status(401).json({ error: INVALID_LOGIN });
    if (u.blocked) return res.status(403).json({ error: 'Account suspended. Contact support.' });
    rl.loginEmail.reset(email);
    if (req.user) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(req.user.token_hash);
    createSession(res, u.id);
    res.json({ ok: true });
  });

  app.post('/api/logout', requireAuth, (req, res) => {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(req.user.token_hash);
    clearCookie(res);
    res.json({ ok: true });
  });

  app.get('/api/me', requireAuth, (req, res) => {
    res.json({ user: publicUser(req.user), csrf: req.user.csrf, minPayout: MIN_PAYOUT_PAISE });
  });

  // ---- Tasks ----
  const countToday = db.prepare(`SELECT COUNT(*) AS c FROM task_attempts WHERE user_id = ? AND type = ? AND status = 'accepted' AND submitted_at >= ?`);

  app.get('/api/tasks', requireAuth, (req, res) => {
    const rows = db.prepare(`SELECT type, COUNT(*) AS c FROM task_attempts WHERE user_id = ? AND status = 'accepted' AND submitted_at >= ? GROUP BY type`)
      .all(req.user.id, T.istDayStart());
    const counts = Object.fromEntries(rows.map((r) => [r.type, r.c]));
    res.json({
      dailyLimit: DAILY_LIMIT,
      types: Object.entries(T.TASK_TYPES).map(([type, t]) => ({ type, name: t.name, reward: t.reward, minAccuracy: t.minAccuracy, doneToday: counts[type] || 0 })),
    });
  });

  app.post('/api/tasks/start', requireAuth, (req, res) => {
    if (!rl.taskStart.hit(String(req.user.id))) return tooMany(res);
    const type = req.body?.type;
    if (typeof type !== 'string' || !Object.hasOwn(T.TASK_TYPES, type)) return bad(res, 'Unknown task type');
    if (countToday.get(req.user.id, type, T.istDayStart()).c >= DAILY_LIMIT) {
      return res.status(429).json({ error: 'Daily limit reached for this task type. Come back tomorrow.' });
    }
    const task = T.generate(type);
    const id = tx(db, () => {
      db.prepare(`UPDATE task_attempts SET status = 'expired' WHERE user_id = ? AND status = 'issued'`).run(req.user.id);
      return Number(db.prepare(`INSERT INTO task_attempts (user_id, type, display, expected, status, issued_at) VALUES (?, ?, ?, ?, 'issued', ?)`)
        .run(req.user.id, type, JSON.stringify(task.display), JSON.stringify(task.expected), Date.now()).lastInsertRowid);
    });
    const meta = T.TASK_TYPES[type];
    res.status(201).json({ id, type, name: meta.name, reward: meta.reward, minAccuracy: meta.minAccuracy, display: task.display, fields: task.fields || null });
  });

  app.post('/api/tasks/:id/submit', requireAuth, (req, res) => {
    const id = idParam(req.params.id);
    const t = id && db.prepare('SELECT * FROM task_attempts WHERE id = ? AND user_id = ?').get(id, req.user.id);
    if (!t) return res.status(404).json({ error: 'Task not found' });
    if (t.status !== 'issued') return res.status(409).json({ error: 'This task was already submitted or has expired' });
    const now = Date.now();
    if (now - t.issued_at > TASK_TTL_MS) {
      db.prepare(`UPDATE task_attempts SET status = 'expired' WHERE id = ? AND status = 'issued'`).run(id);
      return res.status(410).json({ error: 'Task expired. Start a new one.' });
    }
    const expected = JSON.parse(t.expected);
    const answer = T.normalizeAnswer(req.body?.answer, expected);
    if (answer === null) return bad(res, 'Invalid answer format');

    const expectedText = T.joinExpected(expected);
    const acc = T.accuracy(expectedText, answer);
    const meta = T.TASK_TYPES[t.type];
    let status = 'rejected';
    let reason = null;
    if (now - t.issued_at < T.minTimeMs(expectedText)) reason = 'Submitted too quickly. Please type the task yourself.';
    else if (acc < meta.minAccuracy) reason = `Accuracy ${acc}% is below the required ${meta.minAccuracy}%.`;
    else status = 'accepted';
    const reward = status === 'accepted' ? meta.reward : 0;

    const ok = tx(db, () => {
      const r = db.prepare(`UPDATE task_attempts SET status = ?, accuracy = ?, reward_paise = ?, submitted_at = ? WHERE id = ? AND status = 'issued'`)
        .run(status, acc, reward, now, id);
      if (r.changes !== 1) return false;
      if (reward) db.prepare('UPDATE users SET balance_paise = balance_paise + ? WHERE id = ?').run(reward, req.user.id);
      return true;
    });
    if (!ok) return res.status(409).json({ error: 'This task was already submitted' });
    const balance = db.prepare('SELECT balance_paise AS b FROM users WHERE id = ?').get(req.user.id).b;
    res.json({ status, accuracy: acc, reward, reason, balance });
  });

  app.get('/api/history', requireAuth, (req, res) => {
    const rows = db.prepare(`SELECT id, type, status, accuracy, reward_paise AS reward, submitted_at AS submittedAt FROM task_attempts
      WHERE user_id = ? AND status IN ('accepted','rejected') ORDER BY id DESC LIMIT 50`).all(req.user.id);
    res.json({ items: rows.map((r) => ({ ...r, name: T.TASK_TYPES[r.type]?.name || r.type })) });
  });

  // ---- Payouts ----
  app.get('/api/payouts', requireAuth, (req, res) => {
    const items = db.prepare(`SELECT id, amount_paise AS amount, upi_id AS upiId, status, note, created_at AS createdAt, reviewed_at AS reviewedAt
      FROM payouts WHERE user_id = ? ORDER BY id DESC LIMIT 50`).all(req.user.id);
    const balance = db.prepare('SELECT balance_paise AS b FROM users WHERE id = ?').get(req.user.id).b;
    res.json({ balance, minPayout: MIN_PAYOUT_PAISE, upiId: req.user.upi_id, items });
  });

  app.post('/api/payouts', requireAuth, (req, res) => {
    if (!rl.payout.hit(String(req.user.id))) return tooMany(res);
    const upi = sec.cleanUpi(req.body?.upiId);
    if (!upi) return bad(res, 'Enter a valid UPI ID, e.g. name@okaxis');
    // Amount is always the server-side balance; any client-sent amount is ignored.
    const result = tx(db, () => {
      if (db.prepare(`SELECT 1 FROM payouts WHERE user_id = ? AND status = 'pending'`).get(req.user.id)) {
        return { code: 409, body: { error: 'You already have a payout request under review' } };
      }
      const bal = db.prepare('SELECT balance_paise AS b FROM users WHERE id = ?').get(req.user.id).b;
      if (bal < MIN_PAYOUT_PAISE) return { code: 400, body: { error: `Minimum payout is ₹${MIN_PAYOUT_PAISE / 100}` } };
      db.prepare('UPDATE users SET balance_paise = 0, upi_id = ? WHERE id = ?').run(upi, req.user.id);
      const pid = Number(db.prepare(`INSERT INTO payouts (user_id, amount_paise, upi_id, status, created_at) VALUES (?, ?, ?, 'pending', ?)`)
        .run(req.user.id, bal, upi, Date.now()).lastInsertRowid);
      return { code: 201, body: { id: pid, amount: bal, status: 'pending' } };
    });
    res.status(result.code).json(result.body);
  });

  // ---- Business inquiries ----
  app.post('/api/inquiries', (req, res) => {
    if (!rl.inquiry.hit(req.ip)) return tooMany(res);
    const company = sec.cleanText(req.body?.company, 2, 100);
    const email = sec.cleanEmail(req.body?.email);
    const message = sec.cleanText(req.body?.message, 10, 2000);
    if (!company || !email || !message) return bad(res, 'Please fill company, a valid email and a message (10+ characters)');
    db.prepare('INSERT INTO inquiries (company, email, message, created_at) VALUES (?, ?, ?, ?)').run(company, email, message, Date.now());
    res.status(201).json({ ok: true });
  });

  // ---- Admin ----
  app.get('/api/admin/stats', requireAdmin, (req, res) => {
    const one = (sql, ...a) => db.prepare(sql).get(...a);
    res.json({
      users: one('SELECT COUNT(*) AS c FROM users').c,
      tasksToday: one(`SELECT COUNT(*) AS c FROM task_attempts WHERE status = 'accepted' AND submitted_at >= ?`, T.istDayStart()).c,
      pending: one(`SELECT COUNT(*) AS c, COALESCE(SUM(amount_paise),0) AS s FROM payouts WHERE status = 'pending'`),
      paid: one(`SELECT COALESCE(SUM(amount_paise),0) AS s FROM payouts WHERE status = 'paid'`).s,
    });
  });

  app.get('/api/admin/payouts', requireAdmin, (req, res) => {
    const status = ['pending', 'paid', 'rejected'].includes(req.query.status) ? req.query.status : 'pending';
    const items = db.prepare(`
      SELECT p.id, p.amount_paise AS amount, p.upi_id AS upiId, p.status, p.note, p.created_at AS createdAt,
             u.id AS userId, u.name, u.email, u.blocked,
             (SELECT COUNT(*) FROM task_attempts t WHERE t.user_id = u.id AND t.status = 'accepted') AS accepted,
             (SELECT COUNT(*) FROM task_attempts t WHERE t.user_id = u.id AND t.status = 'rejected') AS rejected
      FROM payouts p JOIN users u ON u.id = p.user_id WHERE p.status = ? ORDER BY p.id ${status === 'pending' ? 'ASC' : 'DESC'} LIMIT 200`).all(status);
    res.json({ items });
  });

  app.post('/api/admin/payouts/:id', requireAdmin, (req, res) => {
    const id = idParam(req.params.id);
    const action = req.body?.action;
    if (!id) return res.status(404).json({ error: 'Payout not found' });
    if (action !== 'paid' && action !== 'reject') return bad(res, 'Action must be "paid" or "reject"');
    const note = req.body?.note == null || req.body.note === '' ? null : sec.cleanText(req.body.note, 1, 200);
    if (req.body?.note && !note) return bad(res, 'Note must be up to 200 characters');
    const result = tx(db, () => {
      const p = db.prepare('SELECT * FROM payouts WHERE id = ?').get(id);
      if (!p) return { code: 404, body: { error: 'Payout not found' } };
      if (p.status !== 'pending') return { code: 409, body: { error: 'Payout already processed' } };
      const status = action === 'paid' ? 'paid' : 'rejected';
      db.prepare(`UPDATE payouts SET status = ?, note = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ? AND status = 'pending'`)
        .run(status, note, Date.now(), req.user.id, id);
      if (status === 'rejected') db.prepare('UPDATE users SET balance_paise = balance_paise + ? WHERE id = ?').run(p.amount_paise, p.user_id);
      return { code: 200, body: { id, status } };
    });
    res.status(result.code).json(result.body);
  });

  app.post('/api/admin/users/:id/block', requireAdmin, (req, res) => {
    const id = idParam(req.params.id);
    if (!id) return res.status(404).json({ error: 'User not found' });
    if (typeof req.body?.blocked !== 'boolean') return bad(res, '"blocked" must be true or false');
    if (id === req.user.id) return bad(res, 'You cannot block yourself');
    const r = db.prepare('UPDATE users SET blocked = ? WHERE id = ?').run(req.body.blocked ? 1 : 0, id);
    if (!r.changes) return res.status(404).json({ error: 'User not found' });
    if (req.body.blocked) db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
    res.json({ id, blocked: req.body.blocked });
  });

  app.get('/api/admin/inquiries', requireAdmin, (req, res) => {
    res.json({ items: db.prepare('SELECT id, company, email, message, created_at AS createdAt FROM inquiries ORDER BY id DESC LIMIT 200').all() });
  });

  app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

  // ---- Static site ----
  if (secureCookies) app.use(['/preview', '/preview.html', '/js/preview-mock.js'], (req, res) => res.status(404).type('text/plain').send('Not found'));
  app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'ignore', extensions: ['html'], index: 'index.html' }));
  app.use((req, res) => res.status(404).type('text/plain').send('Not found'));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large' });
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed JSON' });
    if (err.status >= 400 && err.status < 500) return res.status(err.status).json({ error: 'Bad request' });
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  });

  const cleanup = setInterval(() => db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now()), 60 * 60e3);
  cleanup.unref();

  app.locals.db = db;
  return app;
}

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  createApp().listen(port, () => console.log(`TaskWork running at http://localhost:${port}`));
}

module.exports = { createApp, MIN_PAYOUT_PAISE, DAILY_LIMIT };
