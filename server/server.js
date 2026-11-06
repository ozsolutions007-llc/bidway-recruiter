'use strict';
/*
 * BidWay Contractor Recruiter — backend
 *
 * Serves the single-page app and gives it a shared, server-side store in place of the
 * browser's IndexedDB. Three stores mirror the app's object stores exactly:
 *   recipients (keyed by UEI), runs (auto id), kv (keyed by name).
 * Records are stored as JSON blobs so newer versions of the page can add fields freely.
 *
 * Auth and hardening follow the NexusPanel service: bcrypt passwords, lockouts per IP and
 * per username, temporary passwords that must be replaced at first sign-in, optional TOTP,
 * 15-minute inactivity timeout, strict cookies and security headers.
 *
 * Environment: PORT (8081), DATA_DIR (./data), TRUSTED_PROXIES (comma list),
 *              IDLE_TIMEOUT_MS (900000), PUBLIC_DIR (repo root)
 */
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const initSqlJs = require('sql.js');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT, 10) || 8081;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUBLIC_DIR = process.env.PUBLIC_DIR || path.resolve(__dirname, '..');
const DB_PATH = path.join(DATA_DIR, 'recruiter.db');
const SECRET_PATH = path.join(DATA_DIR, '.session-secret');
const CERT_PATH = path.join(DATA_DIR, 'cert.pem');
const KEY_PATH = path.join(DATA_DIR, 'key.pem');
const IDLE_TIMEOUT_MS = parseInt(process.env.IDLE_TIMEOUT_MS, 10) || 15 * 60 * 1000;
const TRUSTED_PROXIES = new Set((process.env.TRUSTED_PROXIES || '').split(',').map(s => s.trim()).filter(Boolean));

fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });

// ── Audit log (stdout → pm2 log) ──
function audit(event, details = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), audit: event, ...details }));
}

// ── Rate limiting ──
const LOGIN_WINDOW_MS = 15 * 60 * 1000, LOGIN_MAX_FAILURES = 5, LOGIN_LOCKOUT_MS = 15 * 60 * 1000;
const LOGIN_GLOBAL_MAX_PER_MIN = 60, SENSITIVE_MAX_PER_15MIN = 10;
const API_MAX_PER_MIN = 3000; // a scan writes one record per company, so this must be generous

class FailureTracker {
  constructor(windowMs, max, lockoutMs) { this.windowMs = windowMs; this.max = max; this.lockoutMs = lockoutMs; this.map = new Map(); }
  check(key) {
    const now = Date.now(), rec = this.map.get(key);
    if (!rec) return { allowed: true };
    rec.failures = rec.failures.filter(t => now - t < this.windowMs);
    if (rec.lockedUntil && now < rec.lockedUntil) return { allowed: false, retryAfterSec: Math.ceil((rec.lockedUntil - now) / 1000) };
    if (rec.failures.length >= this.max) { rec.lockedUntil = now + this.lockoutMs; return { allowed: false, retryAfterSec: Math.ceil(this.lockoutMs / 1000) }; }
    return { allowed: true };
  }
  fail(key) { if (!this.map.has(key)) this.map.set(key, { failures: [] }); this.map.get(key).failures.push(Date.now()); }
  clear(key) { this.map.delete(key); }
  sweep() { const now = Date.now(); for (const [k, r] of this.map) { r.failures = r.failures.filter(t => now - t < this.windowMs); if (!r.failures.length && (!r.lockedUntil || now > r.lockedUntil)) this.map.delete(k); } }
}
class RequestCounter {
  constructor(windowMs, max) { this.windowMs = windowMs; this.max = max; this.map = new Map(); }
  hit(key) {
    const now = Date.now(); let rec = this.map.get(key);
    if (!rec || now >= rec.resetAt) { rec = { count: 0, resetAt: now + this.windowMs }; this.map.set(key, rec); }
    rec.count++;
    return { allowed: rec.count <= this.max, retryAfterSec: Math.ceil((rec.resetAt - now) / 1000) };
  }
  sweep() { const now = Date.now(); for (const [k, r] of this.map) if (now >= r.resetAt) this.map.delete(k); }
}
const loginFailuresByIp = new FailureTracker(LOGIN_WINDOW_MS, LOGIN_MAX_FAILURES, LOGIN_LOCKOUT_MS);
const loginFailuresByUser = new FailureTracker(LOGIN_WINDOW_MS, LOGIN_MAX_FAILURES, LOGIN_LOCKOUT_MS);
const loginGlobal = new RequestCounter(60 * 1000, LOGIN_GLOBAL_MAX_PER_MIN);
const sensitiveByUser = new RequestCounter(15 * 60 * 1000, SENSITIVE_MAX_PER_15MIN);
const apiByIp = new RequestCounter(60 * 1000, API_MAX_PER_MIN);
setInterval(() => { for (const t of [loginFailuresByIp, loginFailuresByUser, loginGlobal, sensitiveByUser, apiByIp]) t.sweep(); }, 10 * 60 * 1000).unref();

function tooMany(res, retryAfterSec, message) {
  res.set('Retry-After', String(retryAfterSec));
  return res.status(429).json({ error: message || `Too many attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
}
function sensitiveLimiter(req, res, next) {
  const key = req.session && req.session.user ? 'u:' + req.session.user.id : 'ip:' + getClientIp(req);
  const r = sensitiveByUser.hit(key);
  if (!r.allowed) { audit('rate_limited', { scope: 'sensitive', key, ip: getClientIp(req) }); return tooMany(res, r.retryAfterSec); }
  next();
}

// ── Password policy ──
const PASSWORD_MIN_LENGTH = 12, TEMP_PASSWORD_MIN_LENGTH = 8, BCRYPT_COST = 12;
const COMMON_PASSWORDS = new Set(['password', 'password1', 'password123', 'admin', 'admin123', 'administrator', 'welcome', 'welcome1',
  'letmein', 'qwerty', '123456', '12345678', '123456789', '1234567890', 'changeme', 'passw0rd', 'p@ssw0rd', 'iloveyou', 'bidway', 'recruiter']);
function validatePassword(pw, username) {
  if (typeof pw !== 'string') return 'Password is required';
  if (pw.length < PASSWORD_MIN_LENGTH) return `Password must be at least ${PASSWORD_MIN_LENGTH} characters`;
  if (pw.length > 128) return 'Password must be 128 characters or fewer';
  if (!/[a-z]/.test(pw)) return 'Password must include a lowercase letter';
  if (!/[A-Z]/.test(pw)) return 'Password must include an uppercase letter';
  if (!/[0-9]/.test(pw)) return 'Password must include a number';
  if (!/[^A-Za-z0-9]/.test(pw)) return 'Password must include a symbol';
  const lower = pw.toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) return 'Password is too common';
  if (username && username.length >= 3 && lower.includes(username.toLowerCase())) return 'Password must not contain the username';
  return null;
}
function validateTempPassword(pw) {
  if (typeof pw !== 'string' || pw.length < TEMP_PASSWORD_MIN_LENGTH) return `Temporary password must be at least ${TEMP_PASSWORD_MIN_LENGTH} characters`;
  if (pw.length > 128) return 'Password must be 128 characters or fewer';
  return null;
}
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), BCRYPT_COST);

// ── Database (sql.js, persisted to disk with a short debounce) ──
let db;
let saveTimer = null;
function saveDb() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => { saveTimer = null; flushDb(); }, 300);
}
function flushDb() {
  if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
  const tmp = DB_PATH + '.tmp';
  fs.writeFileSync(tmp, Buffer.from(db.export()), { mode: 0o600 });
  fs.renameSync(tmp, DB_PATH);
}
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { try { flushDb(); } catch {} process.exit(0); });

async function initDb() {
  const SQL = await initSqlJs();
  db = fs.existsSync(DB_PATH) ? new SQL.Database(fs.readFileSync(DB_PATH)) : new SQL.Database();
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user', totp_secret TEXT DEFAULT NULL, totp_enabled INTEGER DEFAULT 0,
    must_change_password INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_login_at TEXT DEFAULT NULL, last_login_ip TEXT DEFAULT NULL)`);
  try { db.run("ALTER TABLE users ADD COLUMN approved INTEGER DEFAULT 1"); } catch {}
  db.run(`CREATE TABLE IF NOT EXISTS recipients (uei TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT)`);

  const admin = db.exec("SELECT id FROM users WHERE role = 'admin' LIMIT 1");
  if (admin.length === 0) {
    // First run: random temporary password, written to a 0600 file in DATA_DIR, must be changed at first sign-in
    const temp = crypto.randomBytes(9).toString('base64url');
    db.run("INSERT INTO users (username, password, role, must_change_password) VALUES ('admin', ?, 'admin', 1)", [bcrypt.hashSync(temp, BCRYPT_COST)]);
    const f = path.join(DATA_DIR, 'INITIAL_ADMIN_PASSWORD.txt');
    fs.writeFileSync(f, `username: admin\ntemporary password: ${temp}\nYou will be asked to choose a new password at first sign-in. Delete this file afterwards.\n`, { mode: 0o600 });
    console.log(`Default admin created. Temporary password written to ${f}`);
  }
  flushDb();
}

function rowsOf(res) { return res.length > 0 ? res[0].values : []; }
function getUserById(id) {
  const r = rowsOf(db.exec("SELECT id, username, password, role, totp_secret, totp_enabled, must_change_password, approved FROM users WHERE id = ?", [id]))[0];
  return r ? { id: r[0], username: r[1], password: r[2], role: r[3], totp_secret: r[4], totp_enabled: !!r[5], must_change_password: !!r[6], approved: r[7] !== 0 } : null;
}
function getUserByUsername(username) {
  const r = rowsOf(db.exec("SELECT id FROM users WHERE username = ?", [username]))[0];
  return r ? getUserById(r[0]) : null;
}
function publicUser(u) { return { id: u.id, username: u.username, role: u.role }; }

// ── App ──
const app = express();
app.disable('x-powered-by');

// Optional: only accept connections from these peers (the NexusPanel server, which proxies the app).
// With this set, the app is not reachable directly on the LAN or from the internet.
const ALLOWED_PEERS = new Set((process.env.ALLOWED_PEERS || '').split(',').map(s => s.trim()).filter(Boolean));
app.use((req, res, next) => {
  if (ALLOWED_PEERS.size === 0) return next();
  const peer = normalizeIp(req.socket && req.socket.remoteAddress);
  if (ALLOWED_PEERS.has(peer)) return next();
  audit('peer_blocked', { peer, path: req.path });
  res.status(403).type('text').send('This app is only available through NexusPanel.');
});
app.use(express.json({ limit: '256kb' }));

function normalizeIp(ip) { return (ip || '').replace(/^::ffff:/, ''); }
function getClientIp(req) {
  const peer = normalizeIp(req.socket && req.socket.remoteAddress);
  if (TRUSTED_PROXIES.has(peer)) {
    // Cloudflare Tunnel sets CF-Connecting-IP; Nginx Proxy Manager sets X-Real-IP / X-Forwarded-For
    const fwd = req.headers['cf-connecting-ip'] || req.headers['x-real-ip'] || req.headers['x-forwarded-for'];
    if (fwd) return normalizeIp(String(fwd).split(',')[0].trim());
  }
  return peer || 'unknown';
}

// Security headers. The page loads SheetJS from cdnjs and fonts from Google, and calls
// USAspending, SAM.gov, FPDS and Scrape.do directly from the browser. NexusPanel shows this app
// inside its viewer frame, so framing is allowed from those origins only (FRAME_ANCESTORS).
const FRAME_ANCESTORS = (process.env.FRAME_ANCESTORS || '').trim();
app.use((req, res, next) => {
  res.set({
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data:",
      "connect-src 'self' https:",
      "frame-ancestors 'self' " + FRAME_ANCESTORS,
      "form-action 'self'",
      "base-uri 'self'",
      "object-src 'none'"
    ].join('; ')
  });
  if (req.path.startsWith('/api/')) res.set('Cache-Control', 'no-store');
  next();
});

app.use('/api', (req, res, next) => {
  const r = apiByIp.hit(getClientIp(req));
  if (!r.allowed) { audit('rate_limited', { scope: 'api', ip: getClientIp(req) }); return tooMany(res, r.retryAfterSec, 'Too many requests'); }
  next();
});

// Cross-site check for writes (plus SameSite=Strict on the cookie)
app.use('/api', (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  const origin = req.headers.origin;
  if (!origin) return next();
  let host; try { host = new URL(origin).host; } catch { return res.status(403).json({ error: 'Invalid origin' }); }
  if (host !== req.headers.host) { audit('csrf_blocked', { ip: getClientIp(req), origin, host: req.headers.host }); return res.status(403).json({ error: 'Cross-site request blocked' }); }
  next();
});

let sessionSecret;
if (fs.existsSync(SECRET_PATH)) sessionSecret = fs.readFileSync(SECRET_PATH, 'utf8').trim();
else { sessionSecret = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(SECRET_PATH, sessionSecret, { mode: 0o600 }); }

app.use(session({
  name: 'bidway.sid', secret: sessionSecret, resave: false, saveUninitialized: false, rolling: true,
  cookie: { maxAge: 12 * 60 * 60 * 1000, secure: true, httpOnly: true, sameSite: 'none' }
}));

// Inactivity timeout: only requests marked X-Activity: 1 (made shortly after real user input) or writes count
app.use((req, res, next) => {
  if (!req.session || !req.session.user) return next();
  const now = Date.now();
  if (req.session.lastActivity && now - req.session.lastActivity > IDLE_TIMEOUT_MS) {
    const username = req.session.user.username;
    return req.session.destroy(() => {
      res.clearCookie('bidway.sid');
      audit('session_idle_timeout', { username, ip: getClientIp(req) });
      res.status(401).json({ error: 'Signed out after 15 minutes of inactivity', session_expired: true });
    });
  }
  if (!req.session.lastActivity || req.method !== 'GET' || req.headers['x-activity'] === '1') req.session.lastActivity = now;
  next();
});

// A user on a temporary password can only reach what's needed to replace it
const PASSWORD_CHANGE_ALLOWLIST = new Set(['/api/me', '/api/me/password', '/api/logout']);
app.use('/api', (req, res, next) => {
  if (req.session && req.session.user && req.session.user.mustChangePassword && !PASSWORD_CHANGE_ALLOWLIST.has(req.originalUrl.split('?')[0])) {
    return res.status(403).json({ error: 'You must set a new password before continuing', needs_password_change: true });
  }
  next();
});

function requireAuth(req, res, next) { if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' }); next(); }
function requireAdmin(req, res, next) { if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' }); next(); }

// ── Self-service registration ──
// Mode is stored in kv 'registrationMode': 'open' (default: new accounts can sign in at once), 'approval', or 'off'.
const REGISTRATION_MODES = new Set(['approval', 'open', 'off']);
function registrationMode() {
  const r = rowsOf(db.exec("SELECT data FROM kv WHERE k = 'registrationMode'"))[0];
  const item = r ? parseRow(r[0]) : null;
  return item && REGISTRATION_MODES.has(item.v) ? item.v : 'open';
}
const registrationsByIp = new RequestCounter(60 * 60 * 1000, 5);

app.get('/api/register/mode', (req, res) => res.json({ mode: registrationMode() }));

app.post('/api/register', async (req, res) => {
  const ip = getClientIp(req);
  const mode = registrationMode();
  if (mode === 'off') return res.status(403).json({ error: 'Account creation is turned off. Ask an admin for an account.' });
  const r = registrationsByIp.hit(ip);
  if (!r.allowed) { audit('rate_limited', { scope: 'register', ip }); return tooMany(res, r.retryAfterSec, 'Too many accounts created from this address. Try again later.'); }
  const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!/^[A-Za-z0-9._-]{3,32}$/.test(username)) return res.status(400).json({ error: 'Username must be 3-32 characters: letters, numbers, dot, dash or underscore' });
  const problem = validatePassword(password, username);
  if (problem) return res.status(400).json({ error: problem });
  const approved = mode === 'open' ? 1 : 0;
  try {
    db.run("INSERT INTO users (username, password, role, must_change_password, approved) VALUES (?, ?, 'user', 0, ?)", [username, await bcrypt.hash(password, BCRYPT_COST), approved]);
    saveDb();
    audit('user_registered', { username, ip, approved: !!approved });
    res.json({ ok: true, pending: !approved });
  } catch { res.status(400).json({ error: 'That username is taken' }); }
});

// ── Auth ──
async function completeLogin(req, res, user, ip) {
  await new Promise((resolve, reject) => req.session.regenerate(err => (err ? reject(err) : resolve())));
  req.session.user = { ...publicUser(user), mustChangePassword: user.must_change_password };
  req.session.lastActivity = Date.now();
  db.run("UPDATE users SET last_login_at = ?, last_login_ip = ? WHERE id = ?", [new Date().toISOString(), ip, user.id]);
  saveDb();
  loginFailuresByIp.clear(ip); loginFailuresByUser.clear(user.username.toLowerCase());
  audit('login_success', { username: user.username, ip });
  res.json({ user: publicUser(user), needs_password_change: user.must_change_password });
}

app.post('/api/login', async (req, res) => {
  const ip = getClientIp(req);
  const g = loginGlobal.hit('all');
  if (!g.allowed) { audit('rate_limited', { scope: 'login_global', ip }); return tooMany(res, g.retryAfterSec, 'Too many sign-in attempts right now. Try again shortly.'); }
  const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!username || !password || username.length > 64 || password.length > 128) return res.status(400).json({ error: 'Username and password are required' });
  const userKey = username.toLowerCase();
  const ipCheck = loginFailuresByIp.check(ip);
  if (!ipCheck.allowed) { audit('login_locked', { scope: 'ip', ip, username }); return tooMany(res, ipCheck.retryAfterSec); }
  const userCheck = loginFailuresByUser.check(userKey);
  if (!userCheck.allowed) { audit('login_locked', { scope: 'user', ip, username }); return tooMany(res, userCheck.retryAfterSec); }
  try {
    const user = getUserByUsername(username);
    const ok = await bcrypt.compare(password, user ? user.password : DUMMY_HASH);
    if (!user || !ok) {
      loginFailuresByIp.fail(ip); loginFailuresByUser.fail(userKey);
      audit('login_failed', { username, ip });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (!user.approved) {
      audit('login_pending_approval', { username: user.username, ip });
      return res.status(403).json({ error: 'Your account is waiting for an admin to approve it.' });
    }
    if (user.totp_enabled) {
      req.session.pending2fa = { userId: user.id, expires: Date.now() + 5 * 60 * 1000 };
      return res.json({ requires_2fa: true });
    }
    await completeLogin(req, res, user, ip);
  } catch (e) { console.error('login error', e); res.status(500).json({ error: 'Login failed' }); }
});

app.post('/api/login/2fa', async (req, res) => {
  const ip = getClientIp(req);
  const pending = req.session.pending2fa;
  if (!pending || Date.now() > pending.expires) { delete req.session.pending2fa; return res.status(401).json({ error: 'Sign in again' }); }
  const code = typeof req.body.code === 'string' ? req.body.code.trim() : '';
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Enter the 6-digit code' });
  const user = getUserById(pending.userId);
  if (!user || !user.totp_enabled) { delete req.session.pending2fa; return res.status(401).json({ error: 'Sign in again' }); }
  const userKey = user.username.toLowerCase();
  const ipCheck = loginFailuresByIp.check(ip); if (!ipCheck.allowed) return tooMany(res, ipCheck.retryAfterSec);
  const userCheck = loginFailuresByUser.check(userKey); if (!userCheck.allowed) return tooMany(res, userCheck.retryAfterSec);
  if (!authenticator.verify({ token: code, secret: user.totp_secret })) {
    loginFailuresByIp.fail(ip); loginFailuresByUser.fail(userKey);
    audit('2fa_failed', { username: user.username, ip });
    return res.status(401).json({ error: 'Invalid 2FA code' });
  }
  delete req.session.pending2fa;
  try { await completeLogin(req, res, user, ip); } catch (e) { console.error('login error', e); res.status(500).json({ error: 'Login failed' }); }
});

app.post('/api/logout', (req, res) => {
  const username = req.session.user && req.session.user.username, ip = getClientIp(req);
  req.session.destroy(() => { res.clearCookie('bidway.sid'); if (username) audit('logout', { username, ip }); res.json({ ok: true }); });
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
  const user = getUserById(req.session.user.id);
  if (!user) { req.session.destroy(() => {}); return res.status(401).json({ error: 'Not authenticated' }); }
  res.json({ user: { ...publicUser(user), totp_enabled: user.totp_enabled }, needs_password_change: user.must_change_password || !!req.session.user.mustChangePassword });
});

app.post('/api/me/password', requireAuth, sensitiveLimiter, async (req, res) => {
  const ip = getClientIp(req), user = getUserById(req.session.user.id);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const current = typeof req.body.current_password === 'string' ? req.body.current_password : '';
  const next = typeof req.body.new_password === 'string' ? req.body.new_password : '';
  if (!(await bcrypt.compare(current, user.password))) { audit('password_change_failed', { username: user.username, ip }); return res.status(401).json({ error: 'Current password is incorrect' }); }
  const problem = validatePassword(next, user.username);
  if (problem) return res.status(400).json({ error: problem });
  if (next === current) return res.status(400).json({ error: 'New password must be different from the current one' });
  db.run("UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?", [await bcrypt.hash(next, BCRYPT_COST), user.id]);
  saveDb();
  req.session.user.mustChangePassword = false;
  audit('password_changed', { username: user.username, ip });
  res.json({ ok: true });
});

// ── 2FA (optional per user) ──
app.post('/api/2fa/setup', requireAuth, sensitiveLimiter, (req, res) => {
  const secret = authenticator.generateSecret();
  const otpauth = authenticator.keyuri(req.session.user.username, 'BidWay Recruiter', secret);
  QRCode.toDataURL(otpauth, (err, qr) => {
    if (err) return res.status(500).json({ error: 'Failed to generate QR code' });
    db.run("UPDATE users SET totp_secret = ? WHERE id = ?", [secret, req.session.user.id]); saveDb();
    res.json({ qr_code: qr, secret });
  });
});
app.post('/api/2fa/verify', requireAuth, sensitiveLimiter, (req, res) => {
  const user = getUserById(req.session.user.id);
  const code = typeof req.body.code === 'string' ? req.body.code.trim() : '';
  if (!user || !user.totp_secret) return res.status(400).json({ error: 'No 2FA setup in progress' });
  if (!authenticator.verify({ token: code, secret: user.totp_secret })) return res.status(400).json({ error: 'Invalid code. Try again.' });
  db.run("UPDATE users SET totp_enabled = 1 WHERE id = ?", [user.id]); saveDb();
  audit('2fa_enabled', { username: user.username, ip: getClientIp(req) });
  res.json({ ok: true });
});
app.post('/api/2fa/disable', requireAuth, sensitiveLimiter, async (req, res) => {
  const user = getUserById(req.session.user.id);
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const code = typeof req.body.code === 'string' ? req.body.code.trim() : '';
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid password' });
  if (user.totp_enabled && !authenticator.verify({ token: code, secret: user.totp_secret })) return res.status(401).json({ error: 'Invalid 2FA code' });
  db.run("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?", [user.id]); saveDb();
  audit('2fa_disabled', { username: user.username, ip: getClientIp(req) });
  res.json({ ok: true });
});

// ── User management (admin) ──
app.get('/api/users', requireAdmin, (req, res) => {
  const users = rowsOf(db.exec("SELECT id, username, role, totp_enabled, created_at, must_change_password, last_login_at, last_login_ip, approved FROM users ORDER BY approved, username"))
    .map(r => ({ id: r[0], username: r[1], role: r[2], totp_enabled: !!r[3], created_at: r[4], must_change_password: !!r[5], last_login_at: r[6], last_login_ip: r[7], approved: r[8] !== 0 }));
  res.json({ users, registration_mode: registrationMode() });
});
app.post('/api/users', requireAdmin, async (req, res) => {
  const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const role = req.body.role === 'admin' ? 'admin' : 'user';
  if (!/^[A-Za-z0-9._-]{3,32}$/.test(username)) return res.status(400).json({ error: 'Username must be 3-32 characters: letters, numbers, dot, dash or underscore' });
  const problem = validateTempPassword(password);
  if (problem) return res.status(400).json({ error: problem });
  try {
    db.run("INSERT INTO users (username, password, role, must_change_password) VALUES (?, ?, ?, 1)", [username, await bcrypt.hash(password, BCRYPT_COST), role]);
    saveDb();
    audit('user_created', { by: req.session.user.username, username, role, ip: getClientIp(req) });
    res.json({ id: rowsOf(db.exec("SELECT last_insert_rowid()"))[0][0], must_change_password: true });
  } catch { res.status(400).json({ error: 'Username already exists' }); }
});
app.put('/api/users/:id/password', requireAdmin, async (req, res) => {
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const problem = validateTempPassword(password);
  if (problem) return res.status(400).json({ error: problem });
  const target = getUserById(parseInt(req.params.id, 10));
  if (!target) return res.status(404).json({ error: 'User not found' });
  db.run("UPDATE users SET password = ?, must_change_password = 1 WHERE id = ?", [await bcrypt.hash(password, BCRYPT_COST), target.id]); saveDb();
  audit('password_reset_by_admin', { by: req.session.user.username, username: target.username, ip: getClientIp(req) });
  res.json({ ok: true, must_change_password: true });
});
app.put('/api/users/:id/role', requireAdmin, (req, res) => {
  const role = req.body.role === 'admin' ? 'admin' : req.body.role === 'user' ? 'user' : null;
  if (!role) return res.status(400).json({ error: 'Role must be admin or user' });
  const id = parseInt(req.params.id, 10);
  if (id === req.session.user.id) return res.status(400).json({ error: 'You cannot change your own role' });
  const target = getUserById(id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  db.run("UPDATE users SET role = ? WHERE id = ?", [role, id]); saveDb();
  audit('role_changed', { by: req.session.user.username, username: target.username, role, ip: getClientIp(req) });
  res.json({ ok: true });
});
app.post('/api/users/:id/approve', requireAdmin, (req, res) => {
  const target = getUserById(parseInt(req.params.id, 10));
  if (!target) return res.status(404).json({ error: 'User not found' });
  db.run("UPDATE users SET approved = 1 WHERE id = ?", [target.id]); saveDb();
  audit('user_approved', { by: req.session.user.username, username: target.username, ip: getClientIp(req) });
  res.json({ ok: true });
});
app.post('/api/users/:id/2fa/reset', requireAdmin, (req, res) => {
  const target = getUserById(parseInt(req.params.id, 10));
  if (!target) return res.status(404).json({ error: 'User not found' });
  db.run("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?", [target.id]); saveDb();
  audit('2fa_reset_by_admin', { by: req.session.user.username, username: target.username, ip: getClientIp(req) });
  res.json({ ok: true });
});
app.delete('/api/users/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (id === req.session.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  const target = getUserById(id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  db.run("DELETE FROM users WHERE id = ?", [id]); saveDb();
  audit('user_deleted', { by: req.session.user.username, username: target.username, ip: getClientIp(req) });
  res.json({ ok: true });
});

// ── Shared data stores (mirror the page's IndexedDB stores) ──
const UEI_RE = /^[A-Za-z0-9]{1,32}$/;
const KV_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const ADMIN_ONLY_KV = new Set(['scrapeToken', 'registrationMode']); // token: admin-set, team-readable; registration mode: admin-set
function parseRow(json) { try { return JSON.parse(json); } catch { return null; } }
function who(req) { return req.session.user.username; }

app.get('/api/recipients', requireAuth, (req, res) => {
  res.json({ recipients: rowsOf(db.exec("SELECT data FROM recipients")).map(r => parseRow(r[0])).filter(Boolean) });
});
app.get('/api/recipients/:uei', requireAuth, (req, res) => {
  if (!UEI_RE.test(req.params.uei)) return res.status(400).json({ error: 'Invalid UEI' });
  const r = rowsOf(db.exec("SELECT data FROM recipients WHERE uei = ?", [req.params.uei]))[0];
  res.json({ recipient: r ? parseRow(r[0]) : null });
});
app.put('/api/recipients/:uei', requireAuth, (req, res) => {
  const rec = req.body;
  if (!UEI_RE.test(req.params.uei) || !rec || typeof rec !== 'object' || rec.uei !== req.params.uei) return res.status(400).json({ error: 'Record UEI must match the URL' });
  db.run("INSERT OR REPLACE INTO recipients (uei, data, updated_at, updated_by) VALUES (?, ?, ?, ?)", [rec.uei, JSON.stringify(rec), new Date().toISOString(), who(req)]);
  saveDb();
  res.json({ ok: true });
});
app.delete('/api/recipients/:uei', requireAuth, (req, res) => {
  if (!UEI_RE.test(req.params.uei)) return res.status(400).json({ error: 'Invalid UEI' });
  db.run("DELETE FROM recipients WHERE uei = ?", [req.params.uei]); saveDb();
  res.json({ ok: true });
});

app.get('/api/runs', requireAuth, (req, res) => {
  res.json({ runs: rowsOf(db.exec("SELECT id, data FROM runs ORDER BY id")).map(r => ({ ...(parseRow(r[1]) || {}), id: r[0] })) });
});
app.post('/api/runs', requireAuth, (req, res) => {
  const run = req.body;
  if (!run || typeof run !== 'object') return res.status(400).json({ error: 'Run record required' });
  db.run("INSERT INTO runs (data, created_at, created_by) VALUES (?, ?, ?)", [JSON.stringify(run), new Date().toISOString(), who(req)]); saveDb();
  res.json({ id: rowsOf(db.exec("SELECT last_insert_rowid()"))[0][0] });
});

app.get('/api/kv/:k', requireAuth, (req, res) => {
  if (!KV_RE.test(req.params.k)) return res.status(400).json({ error: 'Invalid key' });
  const r = rowsOf(db.exec("SELECT data FROM kv WHERE k = ?", [req.params.k]))[0];
  res.json({ item: r ? parseRow(r[0]) : null });
});
app.put('/api/kv/:k', requireAuth, (req, res) => {
  const item = req.body;
  if (!KV_RE.test(req.params.k) || !item || typeof item !== 'object' || item.k !== req.params.k) return res.status(400).json({ error: 'Item key must match the URL' });
  if (ADMIN_ONLY_KV.has(item.k) && req.session.user.role !== 'admin') return res.status(403).json({ error: 'Only an admin can change the API token' });
  db.run("INSERT OR REPLACE INTO kv (k, data, updated_at, updated_by) VALUES (?, ?, ?, ?)", [item.k, JSON.stringify(item), new Date().toISOString(), who(req)]); saveDb();
  res.json({ ok: true });
});
app.delete('/api/kv/:k', requireAdmin, (req, res) => {
  if (!KV_RE.test(req.params.k)) return res.status(400).json({ error: 'Invalid key' });
  db.run("DELETE FROM kv WHERE k = ?", [req.params.k]); saveDb();
  res.json({ ok: true });
});

// ── Static page: the newest versioned HTML in the repo root ──
function pageFile() {
  const files = fs.readdirSync(PUBLIC_DIR).filter(f => /^bidway-recruiter_v.*\.html$/.test(f))
    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  return files.length ? path.join(PUBLIC_DIR, files[files.length - 1]) : null;
}
app.get('/', (req, res) => {
  const f = pageFile();
  if (!f) return res.status(404).send('App page not found');
  res.set('Cache-Control', 'no-cache');
  res.sendFile(f);
});
app.get('/favicon.ico', (req, res) => res.status(204).end());
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

initDb().then(() => {
  const opts = { key: fs.readFileSync(KEY_PATH), cert: fs.readFileSync(CERT_PATH) };
  https.createServer(opts, app).listen(PORT, '0.0.0.0', () => {
    console.log(`BidWay Recruiter running at https://0.0.0.0:${PORT} serving ${path.basename(pageFile() || '(none)')}`);
  });
});
