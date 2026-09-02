const crypto = require('crypto');

// ---------- IDs & codes ----------

function newId() {
  return crypto.randomUUID();
}

function newToken() {
  return crypto.randomBytes(24).toString('hex');
}

// Code de parrainage : court, lisible, sans caractères ambigus (0/O, 1/I).
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function newShortCode(length = 6) {
  let out = '';
  const bytes = crypto.randomBytes(length);
  for (let i = 0; i < length; i++) {
    out += CODE_ALPHABET[bytes[i] % CODE_ALPHABET.length];
  }
  return out;
}

function newRecoveryCode() {
  return `${newShortCode(4)}-${newShortCode(4)}`;
}

function normalizeName(name) {
  return String(name || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

function normalizeNumber(num) {
  return String(num || '').trim().replace(/\s+/g, '');
}

// ---------- Cookies (pas de dépendance cookie-parser) ----------

function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (key) out[key] = decodeURIComponent(val);
  });
  return out;
}

function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opts.path || '/'}`);
  if (opts.maxAgeSeconds) parts.push(`Max-Age=${opts.maxAgeSeconds}`);
  parts.push('SameSite=Lax');
  if (opts.httpOnly !== false) parts.push('HttpOnly');
  if (process.env.COOKIE_SECURE === 'true') parts.push('Secure');
  const existing = res.getHeader('Set-Cookie');
  const cookieStr = parts.join('; ');
  if (existing) {
    res.setHeader('Set-Cookie', Array.isArray(existing) ? [...existing, cookieStr] : [existing, cookieStr]);
  } else {
    res.setHeader('Set-Cookie', cookieStr);
  }
}

function clearCookie(res, name) {
  setCookie(res, name, '', { maxAgeSeconds: 0 });
}

// ---------- Rate limiting (fenêtre glissante en mémoire) ----------

const rateBuckets = new Map();

function rateLimit({ windowMs, max, keyFn }) {
  return (req, res, next) => {
    const key = (keyFn ? keyFn(req) : req.ip) + '|' + req.baseUrl + req.path;
    const now = Date.now();
    let bucket = rateBuckets.get(key);
    if (!bucket) {
      bucket = [];
      rateBuckets.set(key, bucket);
    }
    while (bucket.length && now - bucket[0] > windowMs) bucket.shift();
    if (bucket.length >= max) {
      return res.status(429).json({ error: 'Trop de tentatives. Réessaie dans un instant.' });
    }
    bucket.push(now);
    next();
  };
}

// ---------- Sessions admin (en mémoire, simples) ----------

const adminSessions = new Map(); // token -> expiry timestamp
const ADMIN_SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h

function createAdminSession() {
  const token = newToken();
  adminSessions.set(token, Date.now() + ADMIN_SESSION_TTL_MS);
  return token;
}

function isAdminSessionValid(token) {
  if (!token) return false;
  const expiry = adminSessions.get(token);
  if (!expiry) return false;
  if (Date.now() > expiry) {
    adminSessions.delete(token);
    return false;
  }
  return true;
}

function destroyAdminSession(token) {
  adminSessions.delete(token);
}

module.exports = {
  newId,
  newToken,
  newShortCode,
  newRecoveryCode,
  normalizeName,
  normalizeNumber,
  parseCookies,
  setCookie,
  clearCookie,
  rateLimit,
  createAdminSession,
  isAdminSessionValid,
  destroyAdminSession,
};
