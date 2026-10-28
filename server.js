'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { loadConfig } = require('./config');
const { openDb, isUniqueError } = require('./db');
const auth = require('./auth');
const { createMailer } = require('./mailer');
const { createLimiter } = require('./ratelimit');
const v = require('./validate');
const { runReminders, stageForNewDoc } = require('./reminders');

const PUBLIC_DIR = path.join(__dirname, 'public');
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png'
};
const MAX_BODY = 20 * 1024;

class HttpError extends Error {
  constructor(status, message, extra) {
    super(message);
    this.status = status;
    this.extra = extra || {};
  }
}

function createApp(config, { logger = console, startTimers = false } = {}) {
  fs.mkdirSync(config.dataDir, { recursive: true });
  const db = openDb(path.join(config.dataDir, 'app.db'));
  const mailer = createMailer(config, logger);

  const loginIp = createLimiter({ windowMs: 15 * 60 * 1000, max: 30 });
  const loginEmail = createLimiter({ windowMs: 15 * 60 * 1000, max: 8 });
  const signupIp = createLimiter({ windowMs: 60 * 60 * 1000, max: 10 });
  const forgotIp = createLimiter({ windowMs: 60 * 60 * 1000, max: 10 });
  const forgotEmail = createLimiter({ windowMs: 60 * 60 * 1000, max: 3 });

  // ---------- helpers ----------
  function clientIp(req) {
    if (config.trustProxy) {
      const xff = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
      if (xff.length) return xff[xff.length - 1];
    }
    return req.socket.remoteAddress || 'unknown';
  }

  function send(res, status, body, headers = {}) {
    const data = body === undefined ? '' : JSON.stringify(body);
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...headers
    });
    res.end(data);
  }

  function readJson(req) {
    return new Promise((resolve, reject) => {
      const type = String(req.headers['content-type'] || '');
      if (!type.toLowerCase().startsWith('application/json')) {
        return reject(new HttpError(415, 'Content-Type must be application/json.'));
      }
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > MAX_BODY) {
          reject(new HttpError(413, 'Request is too large.'));
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on('end', () => {
        try {
          const text = Buffer.concat(chunks).toString('utf8');
          resolve(text ? JSON.parse(text) : {});
        } catch {
          reject(new HttpError(400, 'Invalid JSON.'));
        }
      });
      req.on('error', reject);
    });
  }

  function parseCookies(req) {
    const out = {};
    for (const part of String(req.headers.cookie || '').split(';')) {
      const i = part.indexOf('=');
      if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    }
    return out;
  }

  function cookieHeader(value, maxAgeSec) {
    const parts = [`sid=${value}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAgeSec}`];
    if (config.secureCookies) parts.push('Secure');
    return parts.join('; ');
  }

  function currentUser(req) {
    const token = parseCookies(req).sid;
    if (!token) return null;
    const row = db.prepare(`
      SELECT u.id, u.email, u.email_reminders AS emailReminders
      FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > ?`).get(auth.hashToken(token), Date.now());
    return row ? { id: Number(row.id), email: row.email, emailReminders: !!row.emailReminders } : null;
  }

  function requireUser(req) {
    const user = currentUser(req);
    if (!user) throw new HttpError(401, 'Please log in.');
    return user;
  }

  function startSession(res, userId) {
    const token = auth.newToken();
    db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
      .run(auth.hashToken(token), userId, Date.now() + auth.SESSION_TTL_MS);
    return cookieHeader(token, Math.floor(auth.SESSION_TTL_MS / 1000));
  }

  function tooMany(seconds) {
    return new HttpError(429, 'Too many attempts. Please try again later.', { retryAfter: seconds });
  }

  function docOut(r) {
    return { id: Number(r.id), name: r.name, date: r.date, remind: Number(r.remind) };
  }

  const DOC_COLS = 'id, name, expiry_date AS date, remind_days AS remind';

  // ---------- API ----------
  async function handleApi(req, res, pathname) {
    const method = req.method;

    // Basic CSRF defence: state-changing requests must come from this site.
    if (method !== 'GET' && method !== 'HEAD') {
      const origin = req.headers.origin;
      if (origin) {
        let host = '';
        try { host = new URL(origin).host; } catch { /* ignore */ }
        if (host !== req.headers.host) throw new HttpError(403, 'Cross-site request blocked.');
      }
    }

    if (pathname === '/api/me' && method === 'GET') {
      const user = currentUser(req);
      return send(res, 200, { user });
    }

    if (pathname === '/api/signup' && method === 'POST') {
      const body = await readJson(req);
      const wait = signupIp.consume(clientIp(req));
      if (wait) throw tooMany(wait);
      const email = v.validateEmail(body.email);
      if (!email) throw new HttpError(400, 'Enter a valid email address.');
      const pwError = v.validatePassword(body.password);
      if (pwError) throw new HttpError(400, pwError);
      const hash = await auth.hashPassword(body.password);
      let userId;
      try {
        const r = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email, hash);
        userId = Number(r.lastInsertRowid);
      } catch (e) {
        if (isUniqueError(e)) throw new HttpError(409, 'An account with this email already exists.');
        throw e;
      }
      const cookie = startSession(res, userId);
      return send(res, 201, { user: { id: userId, email, emailReminders: true } }, { 'Set-Cookie': cookie });
    }

    if (pathname === '/api/login' && method === 'POST') {
      const body = await readJson(req);
      const ip = clientIp(req);
      const email = v.validateEmail(body.email) || '';
      const password = typeof body.password === 'string' ? body.password.slice(0, 128) : '';
      const waitIp = loginIp.peek(ip);
      const waitEmail = email ? loginEmail.peek(email) : 0;
      if (waitIp || waitEmail) throw tooMany(Math.max(waitIp, waitEmail));

      const row = email
        ? db.prepare('SELECT id, email, password_hash, email_reminders FROM users WHERE email = ?').get(email)
        : null;
      const ok = await auth.verifyPassword(password, row ? row.password_hash : await auth.dummyHash());
      if (!row || !ok) {
        const w1 = loginIp.consume(ip);
        const w2 = email ? loginEmail.consume(email) : 0;
        if (w1 || w2) throw tooMany(Math.max(w1, w2));
        throw new HttpError(401, 'Incorrect email or password.');
      }
      if (email) loginEmail.reset(email);
      const cookie = startSession(res, Number(row.id));
      return send(res, 200, { user: { id: Number(row.id), email: row.email, emailReminders: !!row.email_reminders } },
        { 'Set-Cookie': cookie });
    }

    if (pathname === '/api/logout' && method === 'POST') {
      const token = parseCookies(req).sid;
      if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(auth.hashToken(token));
      return send(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) });
    }

    if (pathname === '/api/forgot' && method === 'POST') {
      const body = await readJson(req);
      const wait = forgotIp.consume(clientIp(req));
      if (wait) throw tooMany(wait);
      const email = v.validateEmail(body.email);
      // Always give the same answer so the form cannot be used to discover who has an account.
      if (email && !forgotEmail.consume(email)) {
        const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
        if (user) {
          const token = auth.newToken();
          db.prepare('DELETE FROM reset_tokens WHERE user_id = ?').run(user.id);
          db.prepare('INSERT INTO reset_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
            .run(auth.hashToken(token), user.id, Date.now() + auth.RESET_TTL_MS);
          mailer.send({
            to: email,
            subject: 'Reset your Document Expiry Reminder password',
            text: `Hello,\n\nUse this link to choose a new password. It works for one hour:\n\n${config.baseUrl}/#reset=${token}\n\nIf you did not ask for this, you can ignore this email.`
          }).catch((e) => logger.error('Could not send reset email:', e && e.message ? e.message : e));
        }
      }
      return send(res, 200, { ok: true });
    }

    if (pathname === '/api/reset' && method === 'POST') {
      const body = await readJson(req);
      const wait = forgotIp.consume(clientIp(req));
      if (wait) throw tooMany(wait);
      const pwError = v.validatePassword(body.password);
      if (pwError) throw new HttpError(400, pwError);
      const tokenHash = auth.hashToken(body.token);
      const row = db.prepare('SELECT user_id FROM reset_tokens WHERE token_hash = ? AND expires_at > ?')
        .get(tokenHash, Date.now());
      if (!row) throw new HttpError(400, 'This reset link is invalid or has expired.');
      const hash = await auth.hashPassword(body.password);
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, row.user_id);
      db.prepare('DELETE FROM reset_tokens WHERE user_id = ?').run(row.user_id);
      db.prepare('DELETE FROM sessions WHERE user_id = ?').run(row.user_id);
      return send(res, 200, { ok: true });
    }

    if (pathname === '/api/account' && method === 'PATCH') {
      const user = requireUser(req);
      const body = await readJson(req);
      if (typeof body.emailReminders !== 'boolean') throw new HttpError(400, 'Invalid setting.');
      db.prepare('UPDATE users SET email_reminders = ? WHERE id = ?').run(body.emailReminders ? 1 : 0, user.id);
      return send(res, 200, { user: { ...user, emailReminders: body.emailReminders } });
    }

    if (pathname === '/api/account/delete' && method === 'POST') {
      const user = requireUser(req);
      const body = await readJson(req);
      const row = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(user.id);
      const ok = await auth.verifyPassword(typeof body.password === 'string' ? body.password : '', row.password_hash);
      if (!ok) throw new HttpError(403, 'Incorrect password.');
      db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
      return send(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) });
    }

    if (pathname === '/api/documents' && method === 'GET') {
      const user = requireUser(req);
      const rows = db.prepare(`SELECT ${DOC_COLS} FROM documents WHERE user_id = ? ORDER BY expiry_date, name COLLATE NOCASE`).all(user.id);
      return send(res, 200, { documents: rows.map(docOut) });
    }

    if (pathname === '/api/documents' && method === 'POST') {
      const user = requireUser(req);
      const body = await readJson(req);
      const { value, error } = v.validateDocument(body);
      if (error) throw new HttpError(400, error);
      const count = db.prepare('SELECT COUNT(*) AS n FROM documents WHERE user_id = ?').get(user.id).n;
      if (Number(count) >= v.MAX_DOCS_PER_USER) throw new HttpError(400, `You can track up to ${v.MAX_DOCS_PER_USER} documents.`);
      try {
        const r = db.prepare('INSERT INTO documents (user_id, name, expiry_date, remind_days, notified_stage) VALUES (?, ?, ?, ?, ?)')
          .run(user.id, value.name, value.date, value.remind, stageForNewDoc(value.date, new Date()));
        const row = db.prepare(`SELECT ${DOC_COLS} FROM documents WHERE id = ?`).get(r.lastInsertRowid);
        return send(res, 201, { document: docOut(row) });
      } catch (e) {
        if (isUniqueError(e)) throw new HttpError(409, 'You already track a document with that name and expiry date.');
        throw e;
      }
    }

    const m = pathname.match(/^\/api\/documents\/(\d+)$/);
    if (m) {
      const user = requireUser(req);
      const id = Number(m[1]);
      if (method === 'PUT') {
        const body = await readJson(req);
        const { value, error } = v.validateDocument(body);
        if (error) throw new HttpError(400, error);
        const existing = db.prepare('SELECT id FROM documents WHERE id = ? AND user_id = ?').get(id, user.id);
        if (!existing) throw new HttpError(404, 'Document not found.');
        try {
          // Changing the date or warning period starts the reminder cycle again.
          db.prepare(`UPDATE documents SET name = ?, expiry_date = ?, remind_days = ?, notified_stage = ?, updated_at = datetime('now')
                      WHERE id = ? AND user_id = ?`)
            .run(value.name, value.date, value.remind, stageForNewDoc(value.date, new Date()), id, user.id);
        } catch (e) {
          if (isUniqueError(e)) throw new HttpError(409, 'You already track a document with that name and expiry date.');
          throw e;
        }
        const row = db.prepare(`SELECT ${DOC_COLS} FROM documents WHERE id = ?`).get(id);
        return send(res, 200, { document: docOut(row) });
      }
      if (method === 'DELETE') {
        const r = db.prepare('DELETE FROM documents WHERE id = ? AND user_id = ?').run(id, user.id);
        if (!r.changes) throw new HttpError(404, 'Document not found.');
        return send(res, 200, { ok: true });
      }
    }

    throw new HttpError(404, 'Not found.');
  }

  // ---------- static files ----------
  function serveStatic(req, res, pathname) {
    if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Method not allowed.');
    let rel;
    try { rel = decodeURIComponent(pathname); } catch { throw new HttpError(400, 'Bad request.'); }
    if (rel === '/') rel = '/index.html';
    const file = path.normalize(path.join(PUBLIC_DIR, rel));
    if (!file.startsWith(PUBLIC_DIR + path.sep)) throw new HttpError(404, 'Not found.');
    let stat;
    try { stat = fs.statSync(file); } catch { throw new HttpError(404, 'Not found.'); }
    if (!stat.isFile()) throw new HttpError(404, 'Not found.');
    const type = MIME[path.extname(file).toLowerCase()] || 'application/octet-stream';
    res.writeHead(200, {
      'Content-Type': type,
      'Content-Length': stat.size,
      'Cache-Control': 'no-cache'
    });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  }

  const server = http.createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    try {
      const { pathname } = new URL(req.url, 'http://localhost');
      if (pathname.startsWith('/api/')) await handleApi(req, res, pathname);
      else serveStatic(req, res, pathname);
    } catch (err) {
      if (res.headersSent) return res.end();
      if (err instanceof HttpError) {
        const headers = err.extra.retryAfter ? { 'Retry-After': String(err.extra.retryAfter) } : {};
        if (String(req.url).startsWith('/api/')) return send(res, err.status, { error: err.message }, headers);
        res.writeHead(err.status, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end(err.message);
      }
      logger.error('Unexpected error:', err);
      send(res, 500, { error: 'Something went wrong.' });
    }
  });

  const timers = [];
  function cleanup() {
    const now = Date.now();
    db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now);
    db.prepare('DELETE FROM reset_tokens WHERE expires_at <= ?').run(now);
  }
  if (startTimers) {
    const tick = () => runReminders({ db, mailer, baseUrl: config.baseUrl, logger })
      .then((r) => { if (r.emails) logger.log(`[reminders] sent ${r.emails} email(s) covering ${r.documents} document(s)`); })
      .catch((e) => logger.error('Reminder run failed:', e && e.message ? e.message : e));
    timers.push(setTimeout(tick, 3000));
    timers.push(setInterval(tick, config.reminderIntervalMinutes * 60 * 1000));
    timers.push(setInterval(cleanup, 60 * 60 * 1000));
    timers.forEach((t) => t.unref && t.unref());
  }
  cleanup();

  return {
    server,
    db,
    mailer,
    close() {
      timers.forEach((t) => { clearTimeout(t); clearInterval(t); });
      return new Promise((resolve) => server.close(() => { db.close(); resolve(); }));
    }
  };
}

if (require.main === module) {
  const config = loadConfig();
  const app = createApp(config, { startTimers: true });
  app.server.listen(config.port, () => {
    console.log(`Document Expiry Reminder running at ${config.baseUrl}`);
    console.log(app.mailer.usingSmtp
      ? 'Emails are sent through SMTP.'
      : `SMTP is not configured: emails are written to ${path.join(config.dataDir, 'outbox.log')}`);
  });
  const stop = () => app.close().then(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

module.exports = { createApp };
