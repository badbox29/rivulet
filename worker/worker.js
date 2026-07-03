/**
 * ============================================================
 * Rivulet — sync Worker (Cloudflare Workers + KV)
 * ============================================================
 * Backs token and Google accounts. Guest accounts never touch this.
 *
 * Endpoints (the contract auth.js / app.js expect):
 *   GET  /                       → 200 health check
 *   GET  /auth/config            → { googleClientId }   (no secret leaves here)
 *   POST /auth/google            → verify GIS ID token → { ok, kvKey, profile }
 *   POST /auth/verify            → re-verify an ID token → { ok, profile }
 *   POST /auth/migrate           → token → Google (one-way) → { ok, kvKey, profile }
 *   GET  /storage/:key/profile   → read blob (or 410 / X-Token-Migrated)
 *   PUT  /storage/:key/profile   → write blob
 *
 * Auth per request:
 *   Token account  → X-Timestamp + X-Signature (HMAC over the token).
 *                    Derivation MUST match auth.js _deriveHmacKey:
 *                    HKDF(SHA-256, salt='rivulet-hmac-v1', info='request-signing').
 *   Google account → Authorization: Bearer <Google ID token>, verified
 *                    against Google's public keys with aud = GOOGLE_CLIENT_ID.
 *
 * KV layout (binding: RIVULET_KV):
 *   profile:<key>     → the app-data blob. <key> is a token, or "google:<sub>".
 *   forward:<token>   → newToken     (legacy token → secure token upgrade)
 *   tombstone:<token> → newKey       (token → Google migration; old token retired)
 *
 * Env:
 *   GOOGLE_CLIENT_ID  (var)    — public OAuth client ID. '' disables Google auth.
 *   GOOGLE_CLIENT_SECRET       — NOT required: ID-token verification needs only
 *                                Google's public JWKS + the client ID as audience.
 *                                Add it later only if you introduce a code-exchange flow.
 * ============================================================ */

const HMAC_SALT   = 'rivulet-hmac-v1';
const HMAC_INFO   = 'request-signing';
const REPLAY_MS   = 5 * 60 * 1000;          // accepted clock skew for signed requests
const GOOGLE_CERTS = 'https://www.googleapis.com/oauth2/v3/certs';
const GOOGLE_ISS  = ['accounts.google.com', 'https://accounts.google.com'];

// ─── HTTP helpers ─────────────────────────────────────────────────
// ─── Origin allowlist ─────────────────────────────────────────────
// ALLOWED_ORIGINS is a comma-separated list of origins permitted to use this
// worker (e.g. "https://you.github.io,http://localhost:3000"). It's more than
// CORS: unlisted browser origins are rejected outright before any handler runs,
// so the worker won't act as a backend for sites you didn't authorize.
//
// Fails CLOSED: if ALLOWED_ORIGINS is unset or empty, every data/auth route is
// blocked until you configure it — a missing config is loud, not silently open.
// The health check (GET /) stays open so you can confirm the worker is alive.
//
// Caveat: the Origin header is browser-set, so this stops other *websites* and
// casual cross-site abuse, not a direct scripted client (curl) that sets its own
// headers. Real data protection is still the HMAC / Google-token auth on each
// storage and migrate request; this is a defense-in-depth layer on top.
function parseAllowedOrigins(env) {
  return String(env.ALLOWED_ORIGINS || '')
    .split(',').map(s => s.trim()).filter(Boolean);
}

// Resolve the reflected origin for a request, or a verdict for the gate.
//   { allowed: true,  origin }  → permitted; reflect `origin` (may be null for
//                                 non-browser requests with no Origin header)
//   { allowed: false }          → a browser origin that isn't on the list
function resolveOrigin(request, env) {
  const origin = request.headers.get('Origin');
  const list = parseAllowedOrigins(env);
  // No Origin header → not a cross-site browser call. Let it reach the auth
  // layer (which still requires a valid token/signature); nothing to reflect.
  if (!origin) return { allowed: true, origin: null };
  if (list.includes(origin)) return { allowed: true, origin };
  return { allowed: false };
}

// Build CORS headers reflecting a specific allowed origin. When `origin` is a
// concrete allowed value we echo it (and Vary: Origin so caches stay correct);
// when null (non-browser request) we omit the ACAO header entirely.
function cors(origin = null, extra = {}) {
  const headers = {
    'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Timestamp, X-Signature',
    'Access-Control-Expose-Headers': 'X-Token-Migrated',  // so the browser can read it
    'Vary': 'Origin',
    ...extra,
  };
  if (origin) headers['Access-Control-Allow-Origin'] = origin;
  return headers;
}
// Request-scoped reflected origin. Set once at the top of fetch() AFTER the
// origin gate has rejected any disallowed browser origin, so this only ever
// holds one of your own configured origins (or null for non-browser requests).
// Reset per request; handlers read it via cors() without threading a parameter.
let _reqOrigin = null;

function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), {
    status, headers: { 'Content-Type': 'application/json', ...cors(_reqOrigin, extra) },
  });
}
function gone()         { return new Response('Gone', { status: 410, headers: cors(_reqOrigin) }); }
function unauthorized() { return json({ ok: false, error: 'unauthorized' }, 401); }

// A disallowed origin never reaches a handler — rejected at the gate. This
// response deliberately carries no Access-Control-Allow-Origin, so the browser
// blocks the caller from reading it.
function forbiddenOrigin() {
  return new Response(JSON.stringify({ ok: false, error: 'origin not allowed' }), {
    status: 403,
    headers: { 'Content-Type': 'application/json', 'Vary': 'Origin' },
  });
}

// ─── Encoding helpers ─────────────────────────────────────────────
const enc = new TextEncoder();

function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64urlToString(s) { return new TextDecoder().decode(b64urlToBytes(s)); }

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── HMAC verification (token accounts) ───────────────────────────
// Mirrors auth.js: derive an HMAC key from the token via HKDF, then verify
// the signature over `METHOD:token:timestamp:sha256hex(body)`.
async function deriveHmacKey(token) {
  const keyMat = await crypto.subtle.importKey(
    'raw', enc.encode(token), { name: 'HKDF' }, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(HMAC_SALT), info: enc.encode(HMAC_INFO) },
    keyMat,
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['verify']
  );
}

async function verifyHmac(method, token, timestamp, signature, body) {
  if (!timestamp || !signature) return false;
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > REPLAY_MS) return false;
  const bodyHash = await sha256Hex(body || '');
  const message  = `${method.toUpperCase()}:${token}:${timestamp}:${bodyHash}`;
  try {
    const key = await deriveHmacKey(token);
    return await crypto.subtle.verify('HMAC', key, b64urlToBytes(signature), enc.encode(message));
  } catch { return false; }
}

// ─── Google ID token verification (RS256 via JWKS) ────────────────
let _certs = { keys: null, exp: 0 };  // module-scope cache, lives for the isolate's life

async function googleKey(kid) {
  if (!_certs.keys || Date.now() > _certs.exp) {
    const res  = await fetch(GOOGLE_CERTS);
    const data = await res.json();
    const m    = (res.headers.get('cache-control') || '').match(/max-age=(\d+)/);
    _certs = { keys: data.keys || [], exp: Date.now() + (m ? Number(m[1]) * 1000 : 3600 * 1000) };
  }
  return _certs.keys.find(k => k.kid === kid) || null;
}

// Returns the verified payload, or null if anything fails.
async function verifyGoogleIdToken(idToken, clientId) {
  if (!idToken || !clientId) return null;
  const parts = idToken.split('.');
  if (parts.length !== 3) return null;
  let header, payload;
  try {
    header  = JSON.parse(b64urlToString(parts[0]));
    payload = JSON.parse(b64urlToString(parts[1]));
  } catch { return null; }

  const now = Math.floor(Date.now() / 1000);
  if (!GOOGLE_ISS.includes(payload.iss)) return null;
  if (payload.aud !== clientId)          return null;
  if (!payload.exp || payload.exp < now) return null;

  const jwk = await googleKey(header.kid);
  if (!jwk) return null;
  try {
    const key = await crypto.subtle.importKey(
      'jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']
    );
    const ok = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5', key,
      b64urlToBytes(parts[2]),
      enc.encode(`${parts[0]}.${parts[1]}`)
    );
    return ok ? payload : null;
  } catch { return null; }
}

function profileOf(p) {
  return { sub: p.sub, email: p.email || '', name: p.name || '', picture: p.picture || '' };
}

// ─── Per-request storage auth ─────────────────────────────────────
// google:<sub> keys need a matching Bearer ID token; everything else is a
// token account authenticated by HMAC.
async function authStorage(env, method, key, request, body) {
  if (key.startsWith('google:')) {
    const m = (request.headers.get('Authorization') || '').match(/^Bearer (.+)$/);
    if (!m) return false;
    const payload = await verifyGoogleIdToken(m[1], env.GOOGLE_CLIENT_ID);
    return !!payload && key === `google:${payload.sub}`;
  }
  return verifyHmac(method, key,
    request.headers.get('X-Timestamp'),
    request.headers.get('X-Signature'),
    body);
}

// ─── Storage handlers ─────────────────────────────────────────────
async function storageGet(env, key, request) {
  // token → Google migration: old token is retired
  if (await env.RIVULET_KV.get(`tombstone:${key}`)) return gone();

  // legacy → secure token upgrade: forward to the new token and tell the client
  const fwd = await env.RIVULET_KV.get(`forward:${key}`);
  if (fwd) {
    if (!await authStorage(env, 'GET', key, request, '')) return unauthorized();
    const data = await env.RIVULET_KV.get(`profile:${fwd}`, 'json');
    return json({ value: data ?? null }, 200, { 'X-Token-Migrated': fwd });
  }

  if (!await authStorage(env, 'GET', key, request, '')) return unauthorized();
  const data = await env.RIVULET_KV.get(`profile:${key}`, 'json');
  if (data == null) return json({ error: 'not found' }, 404);
  return json({ value: data }, 200);
}

async function storagePut(env, key, request) {
  if (await env.RIVULET_KV.get(`tombstone:${key}`)) return gone();

  const body = await request.text();
  if (!await authStorage(env, 'PUT', key, request, body)) return unauthorized();

  let data;
  try { data = JSON.parse(body); } catch { return json({ error: 'bad json' }, 400); }

  // Legacy → secure token upgrade carries the old token in `_legacyToken`.
  // Stamp a forward pointer so other devices auto-migrate on their next pull.
  if (data._legacyToken && !key.startsWith('google:')) {
    const legacy = String(data._legacyToken);
    delete data._legacyToken;
    await env.RIVULET_KV.put(`profile:${key}`, JSON.stringify(data));
    await env.RIVULET_KV.put(`forward:${legacy}`, key);
    return json({ ok: true });
  }

  await env.RIVULET_KV.put(`profile:${key}`, JSON.stringify(data));
  return json({ ok: true });
}

// ─── Auth handlers ────────────────────────────────────────────────
async function authGoogle(env, request) {
  const { idToken } = await request.json().catch(() => ({}));
  const payload = await verifyGoogleIdToken(idToken, env.GOOGLE_CLIENT_ID);
  if (!payload) return json({ ok: false, error: 'invalid token' }, 401);
  return json({ ok: true, kvKey: `google:${payload.sub}`, profile: profileOf(payload) });
}

async function authVerify(env, request) {
  const { idToken } = await request.json().catch(() => ({}));
  const payload = await verifyGoogleIdToken(idToken, env.GOOGLE_CLIENT_ID);
  if (!payload) return json({ ok: false }, 401);
  return json({ ok: true, profile: profileOf(payload) });
}

// token → Google, one-way. Caller proves the old token via HMAC over the body.
async function authMigrate(env, request) {
  const body = await request.text();
  let parsed;
  try { parsed = JSON.parse(body); } catch { return json({ ok: false, error: 'bad json' }, 400); }
  const { idToken, oldToken } = parsed;
  if (!idToken || !oldToken) return json({ ok: false, error: 'missing fields' }, 400);

  const okHmac = await verifyHmac('POST', oldToken,
    request.headers.get('X-Timestamp'), request.headers.get('X-Signature'), body);
  if (!okHmac) return json({ ok: false, error: 'bad signature' }, 401);

  const payload = await verifyGoogleIdToken(idToken, env.GOOGLE_CLIENT_ID);
  if (!payload) return json({ ok: false, error: 'invalid google token' }, 401);

  const newKey = `google:${payload.sub}`;
  // Refuse if that Google account already exists — this is the 409 the client knows.
  if (await env.RIVULET_KV.get(`profile:${newKey}`)) {
    return json({ ok: false, error: 'account already exists' }, 409);
  }

  const profile = profileOf(payload);
  const data = (await env.RIVULET_KV.get(`profile:${oldToken}`, 'json')) || {};
  data.authMethod   = 'google';
  data.userToken    = newKey;
  data.linkedGoogle = profile;

  await env.RIVULET_KV.put(`profile:${newKey}`, JSON.stringify(data));
  await env.RIVULET_KV.put(`tombstone:${oldToken}`, newKey);  // old token now returns 410
  return json({ ok: true, kvKey: newKey, profile });
}

// ─── Router ───────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url  = new URL(request.url);
    const path = url.pathname;

    // Health check is always open: no data, no auth, reachable in a browser to
    // confirm the worker is alive even before ALLOWED_ORIGINS is configured.
    if (path === '/' && request.method === 'GET') {
      const origin = request.headers.get('Origin');
      const ok = !origin || parseAllowedOrigins(env).includes(origin);
      return new Response('Rivulet sync worker — ok', { status: 200, headers: cors(ok ? origin : null) });
    }

    // Origin gate for everything else. Resolve once, up front; a disallowed
    // browser origin is rejected here before any handler (or preflight) runs.
    const verdict = resolveOrigin(request, env);
    if (!verdict.allowed) return forbiddenOrigin();
    _reqOrigin = verdict.origin;   // request-scoped; only ever an allowed origin

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors(_reqOrigin) });
    }

    try {
      if (path === '/auth/config' && request.method === 'GET') {
        return json({ googleClientId: env.GOOGLE_CLIENT_ID || '' });
      }
      if (path === '/auth/google'  && request.method === 'POST') return authGoogle(env, request);
      if (path === '/auth/verify'  && request.method === 'POST') return authVerify(env, request);
      if (path === '/auth/migrate' && request.method === 'POST') return authMigrate(env, request);

      const m = path.match(/^\/storage\/([^/]+)\/profile$/);
      if (m) {
        const key = decodeURIComponent(m[1]);
        if (request.method === 'GET') return storageGet(env, key, request);
        if (request.method === 'PUT') return storagePut(env, key, request);
      }

      return json({ error: 'not found' }, 404);
    } catch (err) {
      return json({ error: 'server error', detail: String(err && err.message || err) }, 500);
    }
  },
};
