// MediaVerse — Express + Firebase Admin + Cloud Firestore
// Keep Firebase service-account credentials and JWT_SECRET in Render Environment, never in GitHub.
'use strict';

const express = require('express');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const PROD = process.env.NODE_ENV === 'production';
const COOKIE = 'mv_session';
const SESSION_SECONDS = 30 * 24 * 60 * 60; // 30 days
const JWT_SECRET = process.env.JWT_SECRET;
const PUBLIC_DIR = path.join(__dirname, 'public');
// Prefer public/index.html, but also support index.html in the project root.
// Static assets are still served only from /public for safety.
const INDEX_FILE = fs.existsSync(path.join(PUBLIC_DIR, 'index.html'))
  ? path.join(PUBLIC_DIR, 'index.html')
  : path.join(__dirname, 'index.html');

if (!JWT_SECRET || Buffer.byteLength(JWT_SECRET) < 32) {
  console.error('Set JWT_SECRET to a random secret of at least 32 characters in Render Environment.');
  process.exit(1);
}
let serviceAccount;
try { serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_JSON ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON) : null; }
catch { console.error('FIREBASE_SERVICE_ACCOUNT_JSON must contain valid service-account JSON.'); process.exit(1); }
if (!serviceAccount) { console.error('Set FIREBASE_SERVICE_ACCOUNT_JSON in Render Environment.'); process.exit(1); }
if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const FV = admin.firestore.FieldValue;
const TS = admin.firestore.Timestamp;

app.disable('x-powered-by');
app.set('trust proxy', 1); // Render is behind a proxy. Do not use req.ip as a security identity.
app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", 'data:', 'https:'], connectSrc: ["'self'"], fontSrc: ["'self'", 'data:'],
    objectSrc: ["'none'"], baseUri: ["'self'"], frameAncestors: ["'none'"]
  } }
}));
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));
app.use(cookieParser());
app.use(express.static(PUBLIC_DIR, { index: false, maxAge: PROD ? '1h' : 0 }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many login attempts. Please wait a little and try again.' } });
const writeLimiter = rateLimit({ windowMs: 60 * 1000, limit: 25, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'You are posting too quickly. Please wait a moment.' } });
const likeLimiter = rateLimit({ windowMs: 60 * 1000, limit: 60, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Please slow down with likes.' } });
const CATEGORIES = ['Nintendo 3DS / Wii U', 'Nintendo DS / Wii', 'Nintendo Switch Consoles'];
const CONTENT_TYPES = { posts: 'post', discussions: 'discussion', communities: 'community', drawings: 'drawing' };

// Censor abusive terms and IP-looking strings before content is stored or returned.
// This is a basic filter, not a substitute for reports/moderation; it can have false positives.
const BLOCKED_TERMS = [
  'fuck your self', 'fuck yourself', 'kill your self', 'kill yourself', 'fuck you',
  'i like girl juice', 'i lick girls', 'nigger', 'asshole', 'dickhead', 'shit', 'fuck', 'dick'
];
const BLOCKED_REGEX = BLOCKED_TERMS.map(term => new RegExp(`(^|[^a-z0-9])${term.split(' ').map(escapeRegex).join('\\s+')}(?=$|[^a-z0-9])`, 'gi'));
function escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function censor(value) {
  if (typeof value !== 'string') return value;
  let out = value;
  for (const re of BLOCKED_REGEX) out = out.replace(re, (match, prefix = '') => prefix + '#'.repeat(Math.max(3, match.trim().length)));
  // IPv4 addresses and partial dotted quads such as 192.168.145 are masked too.
  out = out.replace(/\b(?:\d{1,3}\s*\.\s*){2,3}\d{0,3}\b/g, m => '#'.repeat(Math.max(7, m.length)));
  return out;
}
function str(value, max, field, required = false) {
  if (typeof value !== 'string') { if (required) throw new Error(`${field} is required.`); return ''; }
  const v = value.trim();
  if (required && !v) throw new Error(`${field} is required.`);
  if (v.length > max) throw new Error(`${field} must be ${max} characters or fewer.`);
  return v;
}
function contentStr(value, max, field, required = false) { return censor(str(value, max, field, required)); }
function safeUrl(value, field, required = false) {
  const raw = str(value, 1500, field, required); if (!raw) return '';
  let u; try { u = new URL(raw); } catch { throw new Error(`${field} must be a valid URL.`); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error(`${field} must use http:// or https://.`);
  return u.href;
}
function slugify(value) {
  return String(value || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase()
    .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || 'item';
}
function iso(v) { return v && typeof v.toDate === 'function' ? v.toDate().toISOString() : (v || null); }
function publicUser(id, d) {
  return { id, username: d.username, bio: d.bio || '', createdAt: iso(d.createdAt), signupAt: iso(d.signupAt || d.createdAt) };
}
function cleanItem(snap) {
  const d = snap.data() || {};
  return { id: snap.id, ...d, createdAt: iso(d.createdAt), updatedAt: iso(d.updatedAt) };
}
function countryFromRequest(req) {
  // Optional: enable only when traffic is guaranteed to pass through your trusted Cloudflare proxy.
  if (process.env.TRUST_COUNTRY_HEADER !== 'true' || !req.get('cf-connecting-ip')) return null;
  const c = (req.get('cf-ipcountry') || '').toUpperCase();
  return /^[A-Z]{2}$/.test(c) && c !== 'XX' ? c : null;
}
function sessionCookieOptions() { return { httpOnly: true, secure: PROD, sameSite: 'lax', path: '/', maxAge: SESSION_SECONDS * 1000 }; }
async function setSession(res, user, country) {
  const sid = crypto.randomUUID();
  const now = Date.now();
  await db.collection('sessions').doc(sid).set({ userId: user.id, username: user.username, createdAt: TS.fromMillis(now), expiresAt: TS.fromMillis(now + SESSION_SECONDS * 1000), lastSeenAt: FV.serverTimestamp(), country: country || null, revoked: false });
  const token = jwt.sign({ sub: user.id, username: user.username, sid }, JWT_SECRET, { expiresIn: SESSION_SECONDS, issuer: 'mediaverse', audience: 'mediaverse-web' });
  res.cookie(COOKIE, token, sessionCookieOptions());
  return sid;
}
function clearSession(res) { res.clearCookie(COOKIE, { httpOnly: true, secure: PROD, sameSite: 'lax', path: '/' }); }
async function optionalAuth(req, res, next) {
  req.user = null; req.sessionId = null; req.securityWarning = null;
  try {
    const token = req.cookies[COOKIE];
    if (!token) return next();
    const decoded = jwt.verify(token, JWT_SECRET, { issuer: 'mediaverse', audience: 'mediaverse-web' });
    if (!decoded.sid || !decoded.sub) throw new Error('Invalid session');
    const sessionRef = db.collection('sessions').doc(decoded.sid);
    const sessionSnap = await sessionRef.get();
    if (!sessionSnap.exists) throw new Error('Session expired');
    const s = sessionSnap.data();
    if (s.revoked || s.userId !== decoded.sub || !s.expiresAt || s.expiresAt.toMillis() <= Date.now()) {
      await sessionRef.set({ revoked: true, revokedAt: FV.serverTimestamp() }, { merge: true });
      throw new Error('Session expired');
    }
    const country = countryFromRequest(req);
    if (country && s.country && country !== s.country) {
      req.securityWarning = 'Your connection appears to be coming from a different country. VPNs, mobile networks, and travel can cause this. For your safety, please log out and log back in if this was not you.';
      await sessionRef.set({ countryChangeAt: FV.serverTimestamp(), countryChangeFrom: s.country, countryChangeTo: country }, { merge: true });
    } else if (country && !s.country) await sessionRef.set({ country }, { merge: true });
    await sessionRef.set({ lastSeenAt: FV.serverTimestamp() }, { merge: true });
    req.user = { id: decoded.sub, username: decoded.username };
    req.sessionId = decoded.sid;
  } catch { clearSession(res); req.user = null; req.sessionId = null; }
  next();
}
function requireAuth(req, res, next) { if (!req.user) return res.status(401).json({ error: 'Please log in again to do that.' }); next(); }
app.use('/api', optionalAuth);

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'MediaVerse' }));
app.get('/api/me', async (req, res) => {
  if (!req.user) return res.json({ user: null, securityWarning: null });
  try {
    const snap = await db.collection('users').doc(req.user.id).get();
    res.json({ user: snap.exists ? { ...publicUser(snap.id, snap.data()), email: snap.data().email || null, lastLoginAt: iso(snap.data().lastLoginAt) } : req.user, securityWarning: req.securityWarning });
  } catch { res.json({ user: req.user, securityWarning: req.securityWarning }); }
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const username = str(req.body.username, 24, 'Username', true);
    if (!/^[a-zA-Z0-9_ -]{3,24}$/.test(username)) return res.status(400).json({ error: 'Username must be 3–24 characters and use letters, numbers, spaces, _ or -.' });
    if (censor(username) !== username) return res.status(400).json({ error: 'Please choose a username without blocked words.' });
    const password = str(req.body.password, 200, 'Password', true);
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    const birthday = str(req.body.birthday, 10, 'Birthday', true);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(birthday) || Number.isNaN(Date.parse(birthday)) || birthday > new Date().toISOString().slice(0, 10)) return res.status(400).json({ error: 'Enter a valid birthday that is not in the future.' });
    const email = str(req.body.email, 254, 'Email');
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address or leave it blank.' });
    const usernameKey = username.toLowerCase().replace(/\s+/g, ' ');
    const indexRef = db.collection('usernameIndex').doc(encodeURIComponent(usernameKey));
    const userRef = db.collection('users').doc();
    const now = TS.now();
    const passwordHash = await bcrypt.hash(password, 12);
    await db.runTransaction(async tx => {
      const exists = await tx.get(indexRef);
      if (exists.exists) throw new Error('That username is already taken. Choose another one.');
      tx.create(userRef, { username, usernameKey, passwordHash, birthday, email: email || null, bio: '', createdAt: now, signupAt: now, lastLoginAt: now, loginHistory: [{ at: now, type: 'signup', country: countryFromRequest(req) }], suspendedUntil: null });
      tx.create(indexRef, { uid: userRef.id });
    });
    const user = { id: userRef.id, username };
    await setSession(res, user, countryFromRequest(req));
    res.status(201).json({ user, profileUrl: `/${encodeURIComponent(username)}` });
  } catch (err) {
    const message = err.message || 'Could not create the account.';
    res.status(message.includes('already taken') ? 409 : 400).json({ error: message });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const username = str(req.body.username, 24, 'Username', true);
    const password = str(req.body.password, 200, 'Password', true);
    const key = username.toLowerCase().replace(/\s+/g, ' ');
    const index = await db.collection('usernameIndex').doc(encodeURIComponent(key)).get();
    if (!index.exists) return res.status(401).json({ error: 'Incorrect username or password.' });
    const userRef = db.collection('users').doc(index.data().uid);
    const snap = await userRef.get();
    if (!snap.exists || !(await bcrypt.compare(password, snap.data().passwordHash))) return res.status(401).json({ error: 'Incorrect username or password.' });
    const d = snap.data();
    if (d.suspendedUntil && d.suspendedUntil.toMillis && d.suspendedUntil.toMillis() > Date.now()) return res.status(403).json({ error: `This account is temporarily suspended until ${d.suspendedUntil.toDate().toISOString()}.` });
    const country = countryFromRequest(req); const previousCountry = d.lastLoginCountry || null;
    const warning = country && previousCountry && country !== previousCountry ? 'This login appears to be from a different country. VPNs, mobile networks, and travel can cause this; please check that it was you.' : null;
    const now = TS.now();
    const history = Array.isArray(d.loginHistory) ? d.loginHistory.slice(-9) : [];
    history.push({ at: now, type: 'login', country: country || null });
    await userRef.update({ lastLoginAt: now, lastLoginCountry: country || previousCountry, loginHistory: history });
    const user = { id: snap.id, username: d.username };
    await setSession(res, user, country);
    res.json({ user, profileUrl: `/${encodeURIComponent(d.username)}`, securityWarning: warning });
  } catch (err) { console.error('Login error:', err); res.status(400).json({ error: 'Could not log in. Please try again.' }); }
});
app.post('/api/auth/logout', async (req, res) => {
  try { if (req.sessionId) await db.collection('sessions').doc(req.sessionId).set({ revoked: true, revokedAt: FV.serverTimestamp() }, { merge: true }); }
  catch (e) { console.error('Session revoke error:', e.message); }
  clearSession(res); res.json({ ok: true });
});

async function getRecent(name, limit = 100) {
  const snap = await db.collection(name).orderBy('createdAt', 'desc').limit(limit).get();
  return snap.docs.map(cleanItem);
}
app.get('/api/data', async (req, res) => {
  try {
    const [communities, posts, discussions, drawings, usersSnap] = await Promise.all([
      getRecent('communities'), getRecent('posts'), getRecent('discussions'), getRecent('drawings'),
      db.collection('users').orderBy('createdAt', 'desc').limit(200).get()
    ]);
    const communitiesByCategory = Object.fromEntries(CATEGORIES.map(c => [c, communities.filter(x => x.category === c)]));
    res.json({ featuredCommunities: communities.filter(x => x.featured).slice(0, 8), communitiesByCategory, posts, discussions, drawings, users: usersSnap.docs.map(s => publicUser(s.id, s.data())) });
  } catch (e) { console.error('Data load failed:', e); res.status(500).json({ error: 'Could not load MediaVerse data.' }); }
});
app.get('/api/users', async (req, res) => {
  try { const s = await db.collection('users').orderBy('createdAt', 'desc').limit(200).get(); res.json({ users: s.docs.map(d => publicUser(d.id, d.data())) }); }
  catch (e) { res.status(500).json({ error: 'Could not load users.' }); }
});

app.patch('/api/me', writeLimiter, requireAuth, async (req, res) => {
  try { const bio = contentStr(req.body.bio, 500, 'Bio'); await db.collection('users').doc(req.user.id).update({ bio, updatedAt: FV.serverTimestamp() }); res.json({ ok: true, bio }); }
  catch (e) { res.status(400).json({ error: e.message || 'Could not update profile.' }); }
});
app.get('/api/account/security', requireAuth, async (req, res) => {
  try { const s = await db.collection('users').doc(req.user.id).get(); if (!s.exists) return res.status(404).json({ error: 'Account not found.' }); const d = s.data(); const ss = req.sessionId ? await db.collection('sessions').doc(req.sessionId).get() : null; const expires = ss && ss.exists ? iso(ss.data().expiresAt) : null; res.json({ signupAt: iso(d.signupAt || d.createdAt), lastLoginAt: iso(d.lastLoginAt), loginHistory: (d.loginHistory || []).map(x => ({ at: iso(x.at), type: x.type, country: x.country || null })), activeSessionExpiresAt: expires }); }
  catch { res.status(500).json({ error: 'Could not load account security information.' }); }
});
app.get('/api/profiles/:username', async (req, res) => {
  try {
    const key = decodeURIComponent(req.params.username).toLowerCase().replace(/\s+/g, ' ');
    const idx = await db.collection('usernameIndex').doc(encodeURIComponent(key)).get();
    if (!idx.exists) return res.status(404).json({ error: 'Profile not found.' });
    const ref = db.collection('users').doc(idx.data().uid); const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ error: 'Profile not found.' });
    const user = publicUser(snap.id, snap.data());
    const [posts, discussions, communities] = await Promise.all(['posts', 'discussions', 'communities'].map(c => db.collection(c).where('creatorId', '==', snap.id).orderBy('createdAt', 'desc').limit(50).get()));
    res.json({ user, posts: posts.docs.map(cleanItem), discussions: discussions.docs.map(cleanItem), communities: communities.docs.map(cleanItem) });
  } catch (e) { console.error('Profile fetch failed:', e); res.status(500).json({ error: 'Could not load profile.' }); }
});

app.post('/api/communities', writeLimiter, requireAuth, async (req, res) => {
  try {
    const name = contentStr(req.body.name, 50, 'Community name', true);
    const description = contentStr(req.body.description, 1200, 'Description', true);
    const category = str(req.body.category, 40, 'Category', true);
    if (!CATEGORIES.includes(category)) return res.status(400).json({ error: 'Choose a valid community category.' });
    const slug = `${slugify(name)}-${crypto.randomBytes(3).toString('hex')}`;
    const item = { name, slug, description, category, icon: safeUrl(req.body.icon, 'Icon URL'), banner: safeUrl(req.body.banner, 'Banner URL'), user: req.user.username, creatorId: req.user.id, featured: false, likeCount: 0, createdAt: FV.serverTimestamp() };
    const ref = await db.collection('communities').add(item);
    res.status(201).json({ item: { id: ref.id, ...item, createdAt: new Date().toISOString(), url: `/community/${slug}` } });
  } catch (e) { res.status(400).json({ error: e.message || 'Could not create community.' }); }
});
async function createContent(req, res, collection, kind) {
  try {
    const title = contentStr(req.body.title, 100, 'Title', true);
    const bodyText = contentStr(req.body.text, 5000, kind === 'drawing' ? 'Description' : 'Text', kind !== 'drawing');
    const community = contentStr(req.body.community, 60, 'Community');
    const slug = `${slugify(title)}-${crypto.randomBytes(3).toString('hex')}`;
    const item = { title, slug, text: bodyText, community, user: req.user.username, creatorId: req.user.id, likeCount: 0, createdAt: FV.serverTimestamp() };
    if (kind === 'drawing') item.image = safeUrl(req.body.image, 'Drawing image URL', true);
    const ref = await db.collection(collection).add(item);
    res.status(201).json({ item: { id: ref.id, ...item, createdAt: new Date().toISOString(), url: `/${kind}/${slug}` } });
  } catch (e) { res.status(400).json({ error: e.message || `Could not create ${kind}.` }); }
}
app.post('/api/posts', writeLimiter, requireAuth, (req, res) => createContent(req, res, 'posts', 'post'));
app.post('/api/discussions', writeLimiter, requireAuth, (req, res) => createContent(req, res, 'discussions', 'discussion'));
app.post('/api/drawings', writeLimiter, requireAuth, (req, res) => createContent(req, res, 'drawings', 'drawing'));

// Likes are stored per user, so repeated taps cannot inflate the count.
app.post('/api/:type/:id/like', likeLimiter, requireAuth, async (req, res) => {
  const collection = CONTENT_TYPES[req.params.type];
  if (!collection || !['posts', 'discussions', 'communities', 'drawings'].includes(req.params.type)) return res.status(404).json({ error: 'Like target not found.' });
  try {
    const target = db.collection(req.params.type).doc(req.params.id);
    const likeRef = target.collection('likes').doc(req.user.id);
    const result = await db.runTransaction(async tx => {
      const [itemSnap, likeSnap] = await Promise.all([tx.get(target), tx.get(likeRef)]);
      if (!itemSnap.exists) throw new Error('Content not found.');
      let count = Number(itemSnap.data().likeCount || 0);
      let liked;
      if (likeSnap.exists) { tx.delete(likeRef); count = Math.max(0, count - 1); liked = false; }
      else { tx.create(likeRef, { userId: req.user.id, createdAt: FV.serverTimestamp() }); count += 1; liked = true; }
      tx.update(target, { likeCount: count, updatedAt: FV.serverTimestamp() });
      return { liked, likeCount: count };
    });
    res.json(result);
  } catch (e) { res.status(e.message === 'Content not found.' ? 404 : 500).json({ error: e.message || 'Could not update like.' }); }
});
app.get('/api/:type/:id/like', requireAuth, async (req, res) => {
  if (!CONTENT_TYPES[req.params.type]) return res.status(404).json({ error: 'Like target not found.' });
  try {
    const target = db.collection(req.params.type).doc(req.params.id);
    const [snap, like] = await Promise.all([target.get(), target.collection('likes').doc(req.user.id).get()]);
    if (!snap.exists) return res.status(404).json({ error: 'Content not found.' });
    res.json({ liked: like.exists, likeCount: Number(snap.data().likeCount || 0) });
  } catch { res.status(500).json({ error: 'Could not check like.' }); }
});

app.get('/api/:type/:id/comments', async (req, res) => {
  if (!CONTENT_TYPES[req.params.type]) return res.status(404).json({ error: 'Content not found.' });
  try { const target = db.collection(req.params.type).doc(req.params.id); const exists = await target.get(); if (!exists.exists) return res.status(404).json({ error: 'Content not found.' }); const snap = await target.collection('comments').orderBy('createdAt', 'asc').limit(100).get(); res.json({ comments: snap.docs.map(d => ({ id: d.id, ...d.data(), createdAt: iso(d.data().createdAt) })) }); }
  catch { res.status(500).json({ error: 'Could not load comments.' }); }
});
app.post('/api/:type/:id/comments', writeLimiter, requireAuth, async (req, res) => {
  if (!CONTENT_TYPES[req.params.type]) return res.status(404).json({ error: 'Content not found.' });
  try { const message = contentStr(req.body.text, 1200, 'Comment', true); const target = db.collection(req.params.type).doc(req.params.id); const exists = await target.get(); if (!exists.exists) return res.status(404).json({ error: 'Content not found.' }); const item = { userId: req.user.id, username: req.user.username, text: message, createdAt: FV.serverTimestamp() }; const ref = await target.collection('comments').add(item); res.status(201).json({ comment: { id: ref.id, ...item, createdAt: new Date().toISOString() } }); }
  catch (e) { res.status(400).json({ error: e.message || 'Could not save comment.' }); }
});

// Individual post/community/discussion pages resolve from Firestore; no separate files need to be created.
const PAGE_TYPES = { post: 'posts', discussion: 'discussions', community: 'communities', drawing: 'drawings' };
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function layout(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · MediaVerse</title><meta name="theme-color" content="#23a66d"><style>body{margin:0;background:#eef8f1;color:#173b2b;font:16px system-ui}header{padding:16px 22px;background:linear-gradient(135deg,#d8f7df,#fff);border-bottom:1px solid #c8e7d2}main{max-width:850px;margin:28px auto;padding:0 16px}.card{background:white;border:1px solid #d6eadb;border-radius:18px;padding:22px;margin:14px 0;box-shadow:0 8px 24px #17472a0d}a{color:#13824e}small{color:#527360}.btn{display:inline-block;background:#168b55;color:white;padding:9px 13px;border-radius:10px;text-decoration:none}</style></head><body><header><a href="/" style="font-weight:800;text-decoration:none;font-size:22px">🍃 MediaVerse</a></header><main>${body}<p><a href="/">← Back to MediaVerse</a></p></main></body></html>`;
}
app.get('/api/content/:type/:slug', async (req, res) => {
  const collection = PAGE_TYPES[req.params.type]; if (!collection) return res.status(404).json({ error: 'Content not found.' });
  try { const s = await db.collection(collection).where('slug', '==', req.params.slug).limit(1).get(); if (s.empty) return res.status(404).json({ error: 'Content not found.' }); res.json({ item: cleanItem(s.docs[0]), type: req.params.type }); }
  catch { res.status(500).json({ error: 'Could not load content.' }); }
});
for (const [route, collection] of Object.entries(PAGE_TYPES)) {
  app.get(`/${route}/:slug`, async (req, res, next) => {
    try {
      const s = await db.collection(collection).where('slug', '==', req.params.slug).limit(1).get();
      if (s.empty) return res.status(404).send(layout('Not found', '<section class="card"><h1>Page not found</h1><p>This MediaVerse page does not exist.</p></section>'));
      const d = s.docs[0].data();
      const image = d.image || d.banner || d.icon;
      const body = `<article class="card"><h1>${esc(d.name || d.title || 'Untitled')}</h1>${d.category ? `<p><small>${esc(d.category)}</small></p>` : ''}<p>${esc(d.description || d.text || '')}</p>${image ? `<p><img src="${esc(image)}" alt="" style="max-width:100%;border-radius:12px"></p>` : ''}<p>By <a href="/${encodeURIComponent(d.user || '')}">${esc(d.user || 'Unknown')}</a> · ♥ ${Number(d.likeCount || 0)}</p><small>Created ${esc(iso(d.createdAt) || 'recently')}</small></article>`;
      res.type('html').send(layout(d.name || d.title || 'MediaVerse', body));
    } catch (e) { next(e); }
  });
}

// /Example is a live profile route: the page is rendered from the users collection.
app.get('/:username', async (req, res, next) => {
  if (req.path.startsWith('/api/') || req.path.includes('.') || ['post','discussion','community','drawing'].includes(req.params.username)) return next();
  try {
    const username = decodeURIComponent(req.params.username);
    const key = username.toLowerCase().replace(/\s+/g, ' ');
    const idx = await db.collection('usernameIndex').doc(encodeURIComponent(key)).get();
    if (!idx.exists) return res.status(404).send(layout('Profile not found', '<section class="card"><h1>Profile not found</h1><p>No MediaVerse account has that username.</p></section>'));
    const snap = await db.collection('users').doc(idx.data().uid).get();
    if (!snap.exists) return res.status(404).send(layout('Profile not found', '<section class="card"><h1>Profile not found</h1></section>'));
    const u = snap.data();
    const [posts, discussions, communities] = await Promise.all(['posts','discussions','communities'].map(c => db.collection(c).where('creatorId','==',snap.id).orderBy('createdAt','desc').limit(20).get()));
    const list = (ss, kind) => ss.docs.map(doc => { const d = doc.data(); return `<div class="card"><h3><a href="/${kind}/${encodeURIComponent(d.slug || doc.id)}">${esc(d.name || d.title || 'Untitled')}</a></h3><p>${esc(d.description || d.text || '')}</p><small>♥ ${Number(d.likeCount || 0)}</small></div>`; }).join('') || '<p><small>Nothing here yet.</small></p>';
    const body = `<section class="card"><h1>${esc(u.username)}</h1><p>${esc(censor(u.bio || 'Welcome to my MediaVerse profile!'))}</p><p><small>Joined ${esc(iso(u.signupAt || u.createdAt) || 'recently')}</small></p></section><h2>Posts</h2>${list(posts,'post')}<h2>Discussions</h2>${list(discussions,'discussion')}<h2>Communities</h2>${list(communities,'community')}`;
    res.type('html').send(layout(`${u.username}'s profile`, body));
  } catch (e) { next(e); }
});

app.use('/api', (req, res) => res.status(404).json({ error: 'API endpoint not found.' }));
app.get(/.*/, (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  if (!fs.existsSync(INDEX_FILE)) {
    return res.status(503).type('text').send('MediaVerse homepage is missing. Add index.html to the public folder or project root.');
  }
  res.sendFile(INDEX_FILE, err => {
    if (err && !res.headersSent) {
      console.error('Could not send homepage:', err.message);
      res.status(500).type('text').send('Could not load the MediaVerse homepage.');
    }
  });
});
app.use((err, req, res, next) => { console.error('Unhandled server error:', err); if (res.headersSent) return next(err); res.status(500).json({ error: 'An unexpected server error occurred.' }); });
app.listen(PORT, () => console.log(`MediaVerse listening on port ${PORT}; session lifetime is 30 days.`));
