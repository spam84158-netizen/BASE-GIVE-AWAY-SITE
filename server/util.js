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

// ---------- Sessions admin (stateless, compatibles Vercel) ----------
// Une session ne doit pas dépendre de la mémoire d'une seule instance
// Serverless : chaque requête peut arriver sur une instance différente.
const ADMIN_SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h

function adminSigningSecret() {
  return String(process.env.COOKIE_SECRET || 'outlaw-mordrex-cookie-secret-change-me');
}

function signAdminPayload(payload) {
  return crypto.createHmac('sha256', adminSigningSecret()).update(payload).digest('hex');
}

function createAdminSession() {
  const payload = `${Date.now() + ADMIN_SESSION_TTL_MS}.${newToken()}`;
  return `${payload}.${signAdminPayload(payload)}`;
}

function isAdminSessionValid(token) {
  if (!token) return false;
  const parts = String(token).split('.');
  if (parts.length !== 3) return false;
  const [expires, nonce, signature] = parts;
  const payload = `${expires}.${nonce}`;
  if (!/^\d+$/.test(expires) || Date.now() > Number(expires)) return false;
  const expected = signAdminPayload(payload);
  try {
    const a = Buffer.from(signature, 'hex');
    const b = Buffer.from(expected, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch (_) {
    return false;
  }
}

function destroyAdminSession(_token) {
  // Session stateless : l'expiration du cookie côté navigateur suffit.
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
