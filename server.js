require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const crypto = require('node:crypto');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { MongoClient, ObjectId, GridFSBucket } = require('mongodb');
const OpenAI = require('openai');

const app = express();
const events = new EventEmitter();
events.setMaxListeners(0);
const PORT = Number(process.env.PORT || 3000);
const DB_NAME = process.env.MONGODB_DB || 'fixbridge';
const SESSION_DAYS = 7;
const COOKIE = 'fixbridge_session';
const MAX_UPLOAD = process.env.NETLIFY || process.env.AWS_LAMBDA_FUNCTION_NAME ? 3 * 1024 * 1024 : 10 * 1024 * 1024;
const MONGO_URI = process.env.MONGODB_URI;
if (!MONGO_URI) throw new Error('MONGODB_URI is required. Copy .env.example to .env and add your MongoDB connection string.');
if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) throw new Error('ADMIN_EMAIL and ADMIN_PASSWORD are required in the private .env file to bootstrap the administrator.');

const mongo = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 10000, maxPoolSize: 20 });
let db, bucket, openai;
let bootstrapPromise;
if (process.env.OPENAI_API_KEY) openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const uploads = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_UPLOAD, files: 2 } });
app.disable('x-powered-by');
if (process.env.NODE_ENV === 'production') app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'same-site' }, contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'], imgSrc: ["'self'", 'data:', 'https://images.unsplash.com'], mediaSrc: ["'self'", 'blob:'], connectSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"], formAction: ["'self'"] } } }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use('/api', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
app.use('/api', (req, res, next) => { const origin = req.get('origin'); if (origin && !['GET','HEAD','OPTIONS'].includes(req.method) && origin !== `${req.protocol}://${req.get('host')}`) return fail(res, 403, 'Cross-origin request blocked.'); next(); });

const safeUser = u => ({ id: String(u._id), name: u.name, email: u.email, role: u.role, approved: !!u.approved, skills: u.skills || '', serviceArea: u.serviceArea || '', experience: u.experience || '', applicationStatus: u.applicationStatus || '' });
const oid = id => ObjectId.isValid(String(id)) ? new ObjectId(String(id)) : null;
const text = (v, max = 500) => String(v || '').trim().slice(0, max);
const emailNorm = v => text(v, 254).toLowerCase();
const hashToken = t => crypto.createHash('sha256').update(t).digest('hex');
const isEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const escapeRx = v => v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const cookieOpts = { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', path: '/' };
const fail = (res, status, message) => res.status(status).json({ error: message });
function publish(type, payload = {}, userIds = null) { events.emit('change', { type, ...payload, userIds }); }
function requireRole(...roles) { return (req, res, next) => { if (!req.user) return fail(res, 401, 'Sign in to continue.'); if (roles.length && !roles.includes(req.user.role)) return fail(res, 403, 'You do not have access to this action.'); next(); }; }
async function auth(req, res, next) {
  try {
    const raw = req.cookies?.[COOKIE] || parseCookie(req.headers.cookie || '')[COOKIE];
    if (!raw) return next();
    const session = await db.collection('sessions').findOne({ tokenHash: hashToken(raw), expiresAt: { $gt: new Date() } });
    if (!session) return next();
    const user = await db.collection('users').findOne({ _id: session.userId, disabled: { $ne: true } });
    if (user) req.user = user;
    next();
  } catch (e) { next(e); }
}
function parseCookie(header) { return Object.fromEntries(header.split(';').map(x => x.trim()).filter(Boolean).map(x => { const i = x.indexOf('='); return [decodeURIComponent(x.slice(0, i)), decodeURIComponent(x.slice(i + 1))]; })); }
app.use(async (_req, _res, next) => { try { await bootstrap(); next(); } catch (e) { next(e); } });
app.use(auth);
async function createSession(res, user) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 86400000);
  await db.collection('sessions').insertOne({ tokenHash: hashToken(token), userId: user._id, createdAt: new Date(), expiresAt });
  res.cookie(COOKIE, token, { ...cookieOpts, maxAge: SESSION_DAYS * 86400000 });
}
async function saveUpload(file, ownerId, purpose) {
  if (!file) return null;
  const allowed = /^(image\/(jpeg|png|webp|gif)|video\/(mp4|webm|quicktime)|application\/pdf|text\/plain)$/i;
  if (!allowed.test(file.mimetype)) throw Object.assign(new Error('Use a JPG, PNG, WebP, GIF, MP4, WebM, PDF or text file.'), { status: 400 });
  const id = new ObjectId();
  const stream = bucket.openUploadStreamWithId(id, path.basename(file.originalname), { contentType: file.mimetype, metadata: { ownerId, purpose, uploadedAt: new Date() } });
  await new Promise((resolve, reject) => { stream.end(file.buffer, error => error ? reject(error) : resolve()); stream.on('error', reject); });
  return { id, name: path.basename(file.originalname), type: file.mimetype, size: file.size };
}
function publicDoc(file) { return file ? { id: String(file.id), name: file.name, type: file.type, size: file.size } : null; }
function requireObjectId(req, res, id) { const value = oid(id); if (!value) { fail(res, 400, 'Invalid record ID.'); return null; } return value; }

app.get('/api/health', async (req, res) => { try { await db.command({ ping: 1 }); res.json({ ok: true, database: 'connected' }); } catch (_) { fail(res, 503, 'Database is unavailable.'); } });
app.get('/api/auth/me', (req, res) => res.json({ user: req.user ? safeUser(req.user) : null }));
app.post('/api/auth/register', uploads.fields([{ name: 'photo', maxCount: 1 }, { name: 'resume', maxCount: 1 }]), async (req, res, next) => {
  try {
    const role = text(req.body.role, 20);
    if (!['customer', 'professional'].includes(role)) return fail(res, 400, 'Choose a customer or professional account.');
    const name = text(req.body.name, 100), email = emailNorm(req.body.email), password = String(req.body.password || '');
    if (name.length < 2 || !isEmail(email) || password.length < 10) return fail(res, 400, 'Enter your name, a valid email, and a password with at least 10 characters.');
    if (role === 'professional' && (!req.files?.photo?.[0]?.mimetype.startsWith('image/') || req.files?.resume?.[0]?.mimetype !== 'application/pdf' || text(req.body.skills, 500).length < 3 || text(req.body.serviceArea, 300).length < 2 || text(req.body.experience, 2000).length < 5)) return fail(res, 400, 'Professional applications need a profile photo, resume PDF, skills, service area and experience.');
    if (await db.collection('users').findOne({ email })) return fail(res, 409, 'An account already exists for this email. Sign in instead.');
    const user = { _id: new ObjectId(), name, email, passwordHash: await bcrypt.hash(password, 12), role, approved: role === 'customer', disabled: false, createdAt: new Date(), updatedAt: new Date(), photo: null, resume: null, skills: text(req.body.skills, 500), serviceArea: text(req.body.serviceArea, 300), experience: text(req.body.experience, 2000), applicationStatus: role === 'professional' ? 'Pending review' : 'Approved', availability: text(req.body.availability, 300) };
    const photo = await saveUpload(req.files?.photo?.[0], user._id, 'profile-photo');
    const resume = await saveUpload(req.files?.resume?.[0], user._id, 'professional-resume'); user.photo = publicDoc(photo); user.resume = publicDoc(resume);
    await db.collection('users').insertOne(user);
    if (role === 'professional') { publish('professional-application', {}, null); return res.status(201).json({ message: 'Professional application submitted. You can sign in after administrator approval.', user: safeUser(user) }); }
    await createSession(res, user); publish('customer-created', {}, [String(user._id)]); res.status(201).json({ user: safeUser(user) });
  } catch (e) { next(e); }
});
const rateBuckets = new Map();
function rateLimit({ key, max, windowMs }) { return (req, res, next) => { const now = Date.now(), identity = `${key}:${req.ip}`; let entry = rateBuckets.get(identity); if (!entry || entry.until < now) entry = { count: 0, until: now + windowMs }; entry.count++; rateBuckets.set(identity, entry); if (rateBuckets.size > 5000) for (const [k,v] of rateBuckets) if (v.until < now) rateBuckets.delete(k); if (entry.count > max) return fail(res, 429, 'Too many requests. Wait a little and try again.'); next(); }; }
app.post('/api/auth/login', rateLimit({ key: 'login', max: 10, windowMs: 15 * 60 * 1000 }), async (req, res, next) => {
  try {
    const email = emailNorm(req.body.email), password = String(req.body.password || ''), user = await db.collection('users').findOne({ email, disabled: { $ne: true } });
    if (!user || !(await bcrypt.compare(password, user.passwordHash || ''))) return fail(res, 401, 'Email or password is incorrect.');
    if (user.role === 'professional' && !user.approved) return fail(res, 403, 'Your professional application is still being reviewed.');
    await createSession(res, user); res.json({ user: safeUser(user) });
  } catch (e) { next(e); }
});
app.post('/api/auth/logout', async (req, res, next) => {
  try { const raw = parseCookie(req.headers.cookie || '')[COOKIE]; if (raw) await db.collection('sessions').deleteOne({ tokenHash: hashToken(raw) }); res.clearCookie(COOKIE, cookieOpts); res.json({ ok: true }); } catch (e) { next(e); }
});

app.get('/api/events', requireRole(), async (req, res) => {
  res.set({ 'Content-Type': 'text/event-stream', 'Connection': 'keep-alive', 'Cache-Control': 'no-cache' }); res.flushHeaders?.();
  res.write(`data: ${JSON.stringify({ type: 'connected' })}\n\n`);
  const listener = event => { if (!event.userIds || event.userIds.includes(String(req.user._id))) res.write(`data: ${JSON.stringify({ type: event.type, id: event.id, status: event.status })}\n\n`); };
  events.on('change', listener); const heartbeat = setInterval(() => res.write(': keep-alive\n\n'), 20000);
  req.on('close', () => { events.off('change', listener); clearInterval(heartbeat); });
});

app.get('/api/requests', requireRole('customer', 'professional', 'admin'), async (req, res, next) => {
  try {
    let query = {};
    if (req.user.role === 'customer') query = { customerId: req.user._id };
    if (req.user.role === 'professional') query = { $or: [{ professionalId: req.user._id }, { professionalId: null, declinedBy: { $ne: req.user._id }, category: { $in: req.user.skills.split(',').map(x => x.trim()).filter(Boolean) } }] };
    const rows = await db.collection('requests').find(query).sort({ createdAt: -1 }).limit(100).toArray(); res.json({ requests: rows });
  } catch (e) { next(e); }
});
app.post('/api/requests', requireRole('customer'), async (req, res, next) => {
  try {
    const category = text(req.body.category, 60), product = text(req.body.product, 100), problem = text(req.body.problem, 2000), address = text(req.body.address, 300), preferredTime = text(req.body.preferredTime, 100);
    if (!category || !product || problem.length < 8 || !address || !preferredTime) return fail(res, 400, 'Complete category, product, problem, service area and preferred time.');
    const doc = { customerId: req.user._id, customerName: req.user.name, customerEmail: req.user.email, category, product, brand: text(req.body.brand, 100), model: text(req.body.model, 100), problem, address, preferredTime, visitFee: 399, estimate: null, status: 'Request received', professionalId: null, professionalName: null, attachments: (Array.isArray(req.body.attachments) ? req.body.attachments : []).map(oid).filter(Boolean), events: [{ status: 'Request received', at: new Date(), by: req.user._id }], createdAt: new Date(), updatedAt: new Date() };
    const result = await db.collection('requests').insertOne(doc); doc._id = result.insertedId; publish('request-created', { id: String(doc._id), status: doc.status }); res.status(201).json({ request: doc });
  } catch (e) { next(e); }
});
app.post('/api/requests/:id/accept', requireRole('professional'), async (req, res, next) => {
  try {
    if (!req.user.approved) return fail(res, 403, 'Professional profile approval is required.'); const id = requireObjectId(req, res, req.params.id); if (!id) return;
    const request = await db.collection('requests').findOneAndUpdate({ _id: id, professionalId: null, category: { $in: req.user.skills.split(',').map(x => x.trim()).filter(Boolean) } }, { $set: { professionalId: req.user._id, professionalName: req.user.name, status: 'Professional assigned', updatedAt: new Date() }, $push: { events: { status: 'Professional assigned', at: new Date(), by: req.user._id } } }, { returnDocument: 'after' });
    if (!request) return fail(res, 409, 'This request was already assigned or does not match your listed skills.'); publish('request-updated', { id: String(id), status: request.status }); res.json({ request });
  } catch (e) { next(e); }
});
app.post('/api/requests/:id/decline', requireRole('professional'), async (req, res, next) => { try { const id = requireObjectId(req, res, req.params.id); if (!id) return; const result = await db.collection('requests').updateOne({ _id: id, professionalId: null, category: { $in: req.user.skills.split(',').map(x => x.trim()).filter(Boolean) } }, { $addToSet: { declinedBy: req.user._id } }); if (!result.modifiedCount) return fail(res, 409, 'This request is no longer available.'); res.json({ ok: true }); } catch (e) { next(e); } });
app.post('/api/requests/:id/estimate', requireRole('professional'), async (req, res, next) => {
  try { const id = requireObjectId(req, res, req.params.id); if (!id) return; const amount = Number(req.body.amount); if (!Number.isFinite(amount) || amount < 1 || amount > 10000000) return fail(res, 400, 'Enter a valid estimate.');
    const request = await db.collection('requests').findOneAndUpdate({ _id: id, professionalId: req.user._id, status: 'Inspection in progress' }, { $set: { estimate: { amount, labour: Number(req.body.labour || 0), parts: Number(req.body.parts || 0), travel: Number(req.body.travel || 0), platformFee: Number(req.body.platformFee || 0), confirmed: false }, status: 'Estimate sent', updatedAt: new Date() }, $push: { events: { status: 'Estimate sent', at: new Date(), by: req.user._id } } }, { returnDocument: 'after' });
    if (!request) return fail(res, 409, 'Start inspection before sending an estimate.'); publish('request-updated', { id: String(id), status: request.status }); res.json({ request });
  } catch (e) { next(e); }
});
app.post('/api/requests/:id/estimate/approve', requireRole('customer'), async (req, res, next) => {
  try { const id = requireObjectId(req, res, req.params.id); if (!id) return; const request = await db.collection('requests').findOneAndUpdate({ _id: id, customerId: req.user._id, status: 'Estimate sent' }, { $set: { status: 'Estimate approved', 'estimate.confirmed': true, updatedAt: new Date() }, $push: { events: { status: 'Estimate approved', at: new Date(), by: req.user._id } } }, { returnDocument: 'after' }); if (!request) return fail(res, 409, 'No pending estimate was found.'); publish('request-updated', { id: String(id), status: request.status }); res.json({ request }); } catch (e) { next(e); }
});
app.patch('/api/requests/:id/status', requireRole('professional'), async (req, res, next) => {
  try { const id = requireObjectId(req, res, req.params.id); if (!id) return; const nextStatus = text(req.body.status, 50); const transitions = { 'Professional assigned': 'On the way', 'On the way': 'Inspection in progress', 'Estimate approved': 'Repair in progress', 'Repair in progress': 'Completed', 'Completed': 'Payment completed' }; if (!transitions[nextStatus] || req.body.nextStatus !== transitions[nextStatus]) return fail(res, 400, 'That status transition is not allowed.'); const request = await db.collection('requests').findOneAndUpdate({ _id: id, professionalId: req.user._id, status: nextStatus }, { $set: { status: req.body.nextStatus, updatedAt: new Date() }, $push: { events: { status: req.body.nextStatus, at: new Date(), by: req.user._id } } }, { returnDocument: 'after' }); if (!request) return fail(res, 409, 'Refresh the request; its status changed.'); publish('request-updated', { id: String(id), status: request.status }); res.json({ request }); } catch (e) { next(e); }
});

app.get('/api/market/listings', async (req, res, next) => {
  try { const q = text(req.query.q, 100), category = text(req.query.category, 60), filter = { status: 'Available' }; if (category) filter.category = category; if (q) { const rx = new RegExp(escapeRx(q), 'i'); filter.$or = ['title','brand','model','category','description','location','condition'].map(k => ({ [k]: rx })); } const listings = await db.collection('listings').find(filter).sort({ createdAt: -1 }).limit(100).toArray(); res.json({ listings }); } catch (e) { next(e); }
});
app.get('/api/market/photos/:id', async (req, res, next) => { try { const id = requireObjectId(req, res, req.params.id); if (!id) return; const listing = await db.collection('listings').findOne({ status: 'Available', photoIds: id }); if (!listing) return fail(res, 404, 'Photo not found.'); const [file] = await db.collection('uploads.files').find({ _id: id }).toArray(); if (!file) return fail(res, 404, 'Photo not found.'); res.set('Content-Type', file.contentType || 'application/octet-stream').set('Cache-Control','public, max-age=300'); bucket.openDownloadStream(id).pipe(res); } catch(e) { next(e); } });
app.post('/api/market/listings', requireRole('customer'), async (req, res, next) => {
  try { const title = text(req.body.title, 150), category = text(req.body.category, 60), price = Number(req.body.price), description = text(req.body.description, 4000); if (title.length < 3 || !category || price < 1 || description.length < 8) return fail(res, 400, 'Add product details, category, valid price and description.'); const l = { title, category, brand: text(req.body.brand, 120), model: text(req.body.model, 120), year: text(req.body.year, 10), condition: text(req.body.condition, 60), description, price, location: text(req.body.location, 300), sellerId: req.user._id, sellerName: req.user.name, status: 'Pending review', photoIds: (req.body.photoIds || []).map(oid).filter(Boolean), createdAt: new Date(), updatedAt: new Date() }; const out = await db.collection('listings').insertOne(l); l._id = out.insertedId; publish('listing-review', { id: String(out.insertedId) }); res.status(201).json({ listing: l }); } catch (e) { next(e); }
});
app.post('/api/market/listings/:id/offers', requireRole('customer'), async (req, res, next) => {
  try { const id = requireObjectId(req, res, req.params.id); if (!id) return; const amount = Number(req.body.amount); if (amount < 1) return fail(res, 400, 'Enter a valid offer.'); const listing = await db.collection('listings').findOne({ _id: id, status: 'Available' }); if (!listing || String(listing.sellerId) === String(req.user._id)) return fail(res, 404, 'Listing not available.'); const offer = { listingId: id, listingTitle: listing.title, sellerId: listing.sellerId, buyerId: req.user._id, buyerName: req.user.name, amount, status: 'Offer received', createdAt: new Date() }; await db.collection('offers').insertOne(offer); publish('offer-received', { id: String(id) }, [String(listing.sellerId)]); res.status(201).json({ message: 'Offer sent to seller.' }); } catch (e) { next(e); }
});
app.post('/api/market/listings/:id/buy', requireRole('customer'), async (req, res, next) => {
  try {
    const id = requireObjectId(req, res, req.params.id); if (!id) return;
    const listing = await db.collection('listings').findOneAndUpdate({ _id: id, status: 'Available', sellerId: { $ne: req.user._id } }, { $set: { status: 'Sold', buyerId: req.user._id, buyerName: req.user.name, soldAt: new Date(), updatedAt: new Date() } }, { returnDocument: 'after' });
    if (!listing) return fail(res, 409, 'This item has just been sold or is no longer available.');
    const commissionRate = (await db.collection('settings').findOne({ _id: 'platform' }))?.commission ?? 10;
    const subtotal = listing.price, platformFee = Math.round(subtotal * commissionRate / 100);
    const order = { receiptNumber: 'FB-'+Date.now().toString(36).toUpperCase(), kind: 'used-product', listingId: id, item: listing.title, buyerId: req.user._id, buyerName: req.user.name, sellerId: listing.sellerId, sellerName: listing.sellerName, subtotal, platformFee, total: subtotal + platformFee, paymentStatus: 'Demo only — no payment processed', status: 'Purchase recorded', createdAt: new Date(), legalNote: 'Not proof of payment or ownership transfer.' };
    try { const saved = await db.collection('orders').insertOne(order); order._id = saved.insertedId; } catch (e) { await db.collection('listings').updateOne({ _id: id, status: 'Sold', buyerId: req.user._id }, { $set: { status: 'Available' }, $unset: { buyerId: '', buyerName: '', soldAt: '' } }); throw e; }
    publish('listing-sold', { id: String(id) }); publish('order-created', { id: String(order._id) }, [String(req.user._id), String(listing.sellerId)]); res.status(201).json({ order });
  } catch (e) { next(e); }
});
app.get('/api/orders', requireRole('customer', 'admin'), async (req, res, next) => { try { const query = req.user.role === 'admin' ? {} : { $or: [{ buyerId: req.user._id }, { sellerId: req.user._id }] }; const orders = await db.collection('orders').find(query).sort({ createdAt: -1 }).limit(100).toArray(); res.json({ orders }); } catch (e) { next(e); } });
app.get('/api/orders/:id/receipt', requireRole('customer','admin'), async (req, res, next) => { try { const id = requireObjectId(req, res, req.params.id); if (!id) return; const order = await db.collection('orders').findOne({ _id: id }); if (!order || (req.user.role !== 'admin' && String(order.buyerId) !== String(req.user._id) && String(order.sellerId) !== String(req.user._id))) return fail(res, 404, 'Receipt not found.'); res.json({ order }); } catch (e) { next(e); } });
app.get('/api/me/listings', requireRole('customer'), async (req, res, next) => { try { const listings = await db.collection('listings').find({ sellerId: req.user._id }).sort({ createdAt: -1 }).limit(100).toArray(); res.json({ listings }); } catch (e) { next(e); } });
app.get('/api/offers', requireRole('customer','admin'), async (req, res, next) => { try { const query = req.user.role === 'admin' ? {} : { $or: [{ buyerId: req.user._id }, { sellerId: req.user._id }] }; const offers = await db.collection('offers').find(query).sort({ createdAt: -1 }).limit(200).toArray(); res.json({ offers }); } catch (e) { next(e); } });
app.post('/api/offers/:id/accept', requireRole('customer'), async (req, res, next) => { try { const id = requireObjectId(req, res, req.params.id); if (!id) return; const offer = await db.collection('offers').findOne({ _id: id, sellerId: req.user._id, status: 'Offer received' }); if (!offer) return fail(res, 404, 'Offer not found.'); const listing = await db.collection('listings').findOneAndUpdate({ _id: offer.listingId, sellerId: req.user._id, status: 'Available' }, { $set: { status: 'Sold', buyerId: offer.buyerId, buyerName: offer.buyerName, soldAt: new Date(), updatedAt: new Date() } }, { returnDocument: 'after' }); if (!listing) return fail(res, 409, 'The listing is no longer available.'); const commissionRate=(await db.collection('settings').findOne({ _id: 'platform' }))?.commission ?? 10, subtotal=offer.amount, platformFee=Math.round(subtotal*commissionRate/100); const order = { receiptNumber: 'FB-'+Date.now().toString(36).toUpperCase(), kind: 'used-product', listingId: listing._id, item: listing.title, buyerId: offer.buyerId, buyerName: offer.buyerName, sellerId: req.user._id, sellerName: req.user.name, subtotal, platformFee, total: subtotal+platformFee, paymentStatus: 'Demo only — no payment processed', status: 'Offer accepted; simulated sale', createdAt: new Date(), legalNote: 'Not proof of payment or ownership transfer.' }; try { const saved = await db.collection('orders').insertOne(order); order._id = saved.insertedId; await db.collection('offers').updateOne({ _id: id }, { $set: { status: 'Accepted', acceptedAt: new Date() } }); } catch (e) { await db.collection('listings').updateOne({ _id: listing._id, status: 'Sold', buyerId: offer.buyerId }, { $set: { status: 'Available' }, $unset: { buyerId: '', buyerName: '', soldAt: '' } }); throw e; } publish('offer-accepted', { id: String(id) }); publish('listing-sold', { id: String(listing._id) }); res.status(201).json({ order, listing }); } catch (e) { next(e); } });
function normalizePart(input) {
  const categories = ['Electronics', 'Home appliances', 'Vehicles', 'Machinery'];
  const part = {
    name: text(input.name, 140), category: text(input.category, 60), productType: text(input.productType, 100),
    brand: text(input.brand, 100), model: text(input.model, 120), compatibility: text(input.compatibility, 500),
    partNumber: text(input.partNumber, 50), keywords: text(input.keywords, 500), price: Number(input.price), stock: Number(input.stock),
    deliveryEstimate: text(input.deliveryEstimate, 120), returns: text(input.returns, 300)
  };
  if (part.name.length < 2 || !categories.includes(part.category) || part.productType.length < 2 || part.brand.length < 1 || part.model.length < 1 || part.compatibility.length < 3 || part.partNumber.length < 2 || !Number.isFinite(part.price) || part.price < 0 || part.price > 100000000 || !Number.isInteger(part.stock) || part.stock < 0 || part.stock > 1000000 || part.deliveryEstimate.length < 2 || part.returns.length < 2) return null;
  return part;
}
app.get('/api/admin/parts', requireRole('admin'), async (req, res, next) => { try { const parts = await db.collection('parts').find({}).sort({ name: 1 }).limit(500).toArray(); res.json({ parts }); } catch (e) { next(e); } });
app.post('/api/admin/parts', requireRole('admin'), async (req, res, next) => {
  try {
    const part = normalizePart(req.body); if (!part) return fail(res, 400, 'Enter a valid part name, category, compatibility, part number, price, stock, delivery estimate and return policy.');
    if (await db.collection('parts').findOne({ partNumber: part.partNumber })) return fail(res, 409, 'That part number is already in use.');
    Object.assign(part, { active: true, createdAt: new Date(), updatedAt: new Date(), updatedBy: req.user._id });
    const saved = await db.collection('parts').insertOne(part); part._id = saved.insertedId; publish('part-updated', { id: String(part._id) }); res.status(201).json({ part });
  } catch (e) { next(e); }
});
app.patch('/api/admin/parts/:id', requireRole('admin'), async (req, res, next) => {
  try {
    const id = requireObjectId(req, res, req.params.id); if (!id) return;
    const changes = typeof req.body.active === 'boolean' ? { active: req.body.active } : normalizePart(req.body);
    if (!changes) return fail(res, 400, 'Enter valid part details and inventory values.');
    if (changes.partNumber && await db.collection('parts').findOne({ partNumber: changes.partNumber, _id: { $ne: id } })) return fail(res, 409, 'That part number is already in use.');
    const updated = await db.collection('parts').findOneAndUpdate({ _id: id }, { $set: { ...changes, updatedAt: new Date(), updatedBy: req.user._id } }, { returnDocument: 'after' });
    if (!updated) return fail(res, 404, 'Spare part not found.'); publish('part-updated', { id: String(id) }); res.json({ part: updated });
  } catch (e) { next(e); }
});
app.get('/api/parts', async (req, res, next) => {
  try { const q = text(req.query.q, 120), category = text(req.query.category, 60), product = text(req.query.product, 100); const filter = { active: { $ne: false } }; if (category) filter.category = category; const and = []; if (q) { const rx = new RegExp(escapeRx(q), 'i'); and.push({ $or: ['name','category','productType','brand','model','compatibility','partNumber','keywords'].map(k => ({ [k]: rx })) }); } if (product) { const rx = new RegExp(escapeRx(product), 'i'); and.push({ $or: [{ productType: rx }, { compatibility: rx }, { model: rx }] }); } if (and.length) filter.$and = and; const parts = await db.collection('parts').find(filter).sort({ name: 1 }).limit(100).toArray(); res.json({ parts, total: parts.length }); } catch (e) { next(e); }
});
app.post('/api/orders/parts', requireRole('customer'), async (req, res, next) => {
  try {
    const id = oid(req.body.partId); if (!id) return fail(res, 400, 'Choose a valid part.');
    const part = await db.collection('parts').findOne({ _id: id, active: { $ne: false } }); if (!part || part.stock < 1) return fail(res, 404, 'Part is unavailable.');
    const stock = await db.collection('parts').updateOne({ _id: part._id, stock: { $gt: 0 } }, { $inc: { stock: -1 } }); if (!stock.modifiedCount) return fail(res, 409, 'This part just sold out. Refresh the catalog.');
    const commissionRate = (await db.collection('settings').findOne({ _id: 'platform' }))?.commission ?? 10, subtotal = part.price, platformFee = Math.round(subtotal * commissionRate / 100);
    const order = { receiptNumber: 'FB-'+Date.now().toString(36).toUpperCase(), kind: 'part', item: part.name, partId: part._id, buyerId: req.user._id, buyerName: req.user.name, subtotal, platformFee, total: subtotal + platformFee, paymentStatus: 'Demo only — no payment processed', status: 'Demo order placed', deliveryEstimate: 'Sample delivery 3–5 days', createdAt: new Date(), legalNote: 'No payment was processed.' };
    try { const result = await db.collection('orders').insertOne(order); order._id = result.insertedId; } catch (e) { await db.collection('parts').updateOne({ _id: part._id }, { $inc: { stock: 1 } }); throw e; }
    res.status(201).json({ order });
  } catch (e) { next(e); }
});

app.post('/api/uploads', requireRole('customer','professional'), uploads.single('file'), async (req, res, next) => { try { if (!req.file) return fail(res, 400, 'Choose a file to upload.'); const file = await saveUpload(req.file, req.user._id, text(req.body.purpose, 50) || 'attachment'); res.status(201).json({ file: publicDoc(file) }); } catch (e) { next(e); } });
app.get('/api/uploads/:id', requireRole('customer','professional','admin'), async (req, res, next) => { try { const id = requireObjectId(req, res, req.params.id); if (!id) return; const [file] = await db.collection('uploads.files').find({ _id: id }).toArray(); if (!file) return fail(res, 404, 'File not found.'); let allowed = req.user.role === 'admin' || String(file.metadata?.ownerId) === String(req.user._id); if (!allowed && req.user.role === 'professional') allowed = !!(await db.collection('requests').findOne({ professionalId: req.user._id, attachments: id })); if (!allowed && req.user.role === 'customer') allowed = !!(await db.collection('listings').findOne({ status: 'Available', photoIds: id })); if (!allowed) return fail(res, 403, 'You cannot access this file.'); res.set('Content-Type', file.contentType || 'application/octet-stream').set('Content-Disposition', `inline; filename="${encodeURIComponent(file.filename)}"`); bucket.openDownloadStream(id).pipe(res); } catch (e) { next(e); } });

const dangerous = /\b(high[ -]?voltage|mains|live wire|electrical panel|gas|gas leak|gas line|stove|boiler|brakes?|air\s?bags?|fuel|refrigerant|compressor gas|heavy machinery|industrial press)\b/i;
const safetyReply = 'This may involve a hazardous system. Stop using it and contact a qualified professional. I can’t provide repair steps for high-voltage electricity, gas, brakes or airbags, fuel systems, heavy machinery, or refrigerants.';
const aiInstructions = `You are FixBridge's preliminary troubleshooting helper. Be careful, factual, and concise. Clearly say possible causes are not a diagnosis. Give only simple external checks a customer can perform safely. Never instruct users to open devices, bypass protection, touch mains/high-voltage electricity, work on gas, brakes/airbags, fuel systems, heavy machinery, or refrigerants. When uncertain, state uncertainty and recommend a professional. Never claim a professional is verified. Offer to browse parts or book a professional.`;
app.post('/api/assistant', requireRole('customer'), rateLimit({ key: 'assistant', max: 20, windowMs: 60 * 1000 }), uploads.single('file'), async (req, res, next) => {
  try {
    const question = text(req.body.message, 3000); if (question.length < 2) return fail(res, 400, 'Describe the issue first.');
    let attachment = null;
    if (req.file && !(req.file.mimetype.startsWith('image/') || ['application/pdf','text/plain'].includes(req.file.mimetype))) return fail(res, 400, 'Assistant uploads support images, PDF and plain text only.');
    if (req.file) { attachment = await saveUpload(req.file, req.user._id, 'assistant-attachment'); }
    if (dangerous.test(question)) { const answer = safetyReply; await db.collection('assistantMessages').insertOne({ userId: req.user._id, question, answer, attachment, createdAt: new Date(), provider: 'safety-rule' }); return res.json({ answer, preliminary: true, safety: true }); }
    if (!openai) return fail(res, 503, 'AI is not configured yet. Add OPENAI_API_KEY to the private .env file to enable the assistant.');
    const content = [{ type: 'input_text', text: question }];
    if (req.file) { const data = req.file.buffer.toString('base64'); if (req.file.mimetype.startsWith('image/')) content.push({ type: 'input_image', image_url: `data:${req.file.mimetype};base64,${data}`, detail: 'high' }); else if (req.file.mimetype === 'application/pdf') content.push({ type: 'input_file', filename: req.file.originalname, file_data: `data:application/pdf;base64,${data}` }); else if (req.file.mimetype === 'text/plain') content.push({ type: 'input_text', text: req.file.buffer.toString('utf8').slice(0, 12000) }); else return fail(res, 400, 'Assistant uploads support images, PDF and plain text only.'); }
    const response = await openai.responses.create({ model: process.env.OPENAI_MODEL || 'gpt-5', instructions: aiInstructions, input: [{ role: 'user', content }], max_output_tokens: 700, store: false });
    const answer = response.output_text || 'I could not produce a reliable suggestion. Please book a professional.';
    await db.collection('assistantMessages').insertOne({ userId: req.user._id, question, answer, attachment, createdAt: new Date(), provider: 'openai', model: process.env.OPENAI_MODEL || 'gpt-5' }); res.json({ answer, preliminary: true, safety: false });
  } catch (e) { next(e); }
});

app.get('/api/admin/overview', requireRole('admin'), async (req, res, next) => { try { const [users, pros, listings, requests, orders] = await Promise.all([db.collection('users').countDocuments(), db.collection('users').countDocuments({ role: 'professional', applicationStatus: 'Pending review' }), db.collection('listings').countDocuments({ status: 'Pending review' }), db.collection('requests').countDocuments({ status: { $nin: ['Completed','Payment completed'] } }), db.collection('orders').countDocuments()]); res.json({ users, pendingProfessionals: pros, pendingListings: listings, activeRequests: requests, orders }); } catch (e) { next(e); } });
app.get('/api/admin/users', requireRole('admin'), async (req, res, next) => { try { const role = text(req.query.role, 20); const filter = role ? { role } : {}; const users = await db.collection('users').find(filter, { projection: { passwordHash: 0 } }).sort({ createdAt: -1 }).limit(300).toArray(); res.json({ users: users.map(safeUser) }); } catch (e) { next(e); } });
app.get('/api/admin/professionals', requireRole('admin'), async (req, res, next) => { try { const users = await db.collection('users').find({ role: 'professional' }).sort({ createdAt: -1 }).limit(200).toArray(); res.json({ professionals: users.map(u => ({ ...safeUser(u), photo: publicDoc(u.photo), resume: publicDoc(u.resume) })) }); } catch (e) { next(e); } });
app.patch('/api/admin/professionals/:id', requireRole('admin'), async (req, res, next) => { try { const id = requireObjectId(req, res, req.params.id); if (!id) return; const decision = text(req.body.decision, 20); if (!['approve','reject'].includes(decision)) return fail(res, 400, 'Choose approve or reject.'); const user = await db.collection('users').findOneAndUpdate({ _id: id, role: 'professional' }, { $set: { approved: decision === 'approve', applicationStatus: decision === 'approve' ? 'Approved' : 'Rejected', reviewedAt: new Date(), reviewedBy: req.user._id, updatedAt: new Date() } }, { returnDocument: 'after' }); if (!user) return fail(res, 404, 'Professional application not found.'); publish('professional-reviewed', {}, [String(id)]); res.json({ user: safeUser(user) }); } catch (e) { next(e); } });
app.get('/api/admin/listings', requireRole('admin'), async (req, res, next) => { try { const listings = await db.collection('listings').find({}).sort({ createdAt: -1 }).limit(300).toArray(); res.json({ listings }); } catch (e) { next(e); } });
app.patch('/api/admin/listings/:id', requireRole('admin'), async (req, res, next) => { try { const id = requireObjectId(req, res, req.params.id); if (!id) return; const action = text(req.body.action, 20); const status = action === 'approve' ? 'Available' : action === 'reject' ? 'Rejected' : null; if (!status) return fail(res, 400, 'Choose approve or reject.'); const listing = await db.collection('listings').findOneAndUpdate({ _id: id, status: 'Pending review' }, { $set: { status, reviewedAt: new Date(), updatedAt: new Date() } }, { returnDocument: 'after' }); if (!listing) return fail(res, 404, 'Pending listing not found.'); publish('listing-reviewed', { id: String(id) }, [String(listing.sellerId)]); res.json({ listing }); } catch (e) { next(e); } });
app.put('/api/admin/settings', requireRole('admin'), async (req, res, next) => { try { const commission = Number(req.body.commission); if (!Number.isFinite(commission) || commission < 0 || commission > 30) return fail(res, 400, 'Commission must be between 0 and 30.'); await db.collection('settings').updateOne({ _id: 'platform' }, { $set: { commission, updatedAt: new Date(), updatedBy: req.user._id } }, { upsert: true }); res.json({ commission }); } catch (e) { next(e); } });

app.get('/api/settings', async (req, res, next) => { try { const settings = await db.collection('settings').findOne({ _id: 'platform' }); res.json({ commission: settings?.commission ?? 10 }); } catch (e) { next(e); } });
app.get('/api/categories', (req, res) => res.json({ categories: ['Electronics','Home appliances','Vehicles','Machinery'] }));
if (!process.env.NETLIFY && !process.env.AWS_LAMBDA_FUNCTION_NAME) app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'], maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0 }));
app.use((req, res) => req.path.startsWith('/api/') ? fail(res, 404, 'API route not found.') : res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use((err, req, res, next) => { console.error(err.message); if (err instanceof multer.MulterError) return fail(res, 400, err.code === 'LIMIT_FILE_SIZE' ? 'File exceeds the 10 MB limit.' : 'Upload could not be processed.'); fail(res, err.status || 500, err.status ? err.message : 'The server could not complete this request. Check server logs.'); });

const baseParts = [
  ['USB-C charging port','Electronics','Mobile phone','Samsung','Galaxy A54','Charging replacement port','USB charging, phone repair'],['iPhone 13 screen assembly','Electronics','Mobile phone','Apple','iPhone 13','Screen assembly; verify exact model','display, screen, phone'],['iPhone 12 battery','Electronics','Mobile phone','Apple','iPhone 12','Battery replacement; professional fitting recommended','battery, phone'],['Galaxy S22 charging flex','Electronics','Mobile phone','Samsung','Galaxy S22','Charging flex assembly','charging, phone'],['Android USB-C cable','Electronics','Mobile phone','Universal','USB-C','Cable only; verify charging standard','cable, charger'],['Laptop cooling fan','Electronics','Laptop','Dell','Inspiron 15','Check laptop service tag and fan part number','fan, laptop, cooling'],['Laptop SSD 512GB','Electronics','Laptop','Universal','M.2 NVMe','Confirm keying and device support','SSD, storage, laptop'],['Laptop 65W adapter','Electronics','Laptop','Universal','USB-C PD','Confirm wattage and connector requirements','adapter, charger'],['Laptop keyboard assembly','Electronics','Laptop','HP','Pavilion 14','Match exact product number before ordering','keyboard, laptop'],['LED TV remote control','Electronics','Television','Universal','IR remote','Confirm TV model and remote compatibility','remote, tv'],['TV HDMI port board','Electronics','Television','Samsung','32 inch selected models','Check board number on original part','HDMI, tv board'],['Wi-Fi router power adapter','Electronics','Router','Universal','12V selected routers','Match voltage, polarity and connector','router, adapter'],['Refrigerator door gasket','Home appliances','Refrigerator','LG','Selected double-door models','Measure and verify model sticker','gasket, fridge, seal'],['Refrigerator thermostat sensor','Home appliances','Refrigerator','Whirlpool','Selected models','Compatibility varies by model','sensor, fridge'],['Washing machine inlet valve','Home appliances','Washing machine','IFB','Front-load selected models','Verify part number and water inlet','valve, washer'],['Washing machine drain pump','Home appliances','Washing machine','LG','Selected front-load models','Confirm pump connector and model','pump, washer'],['Universal appliance belt','Home appliances','Washing machine','Universal','Selected top-load models','Measure old belt; check model compatibility','belt, washer'],['Ceiling fan capacitor 2.5µF','Home appliances','Fan','Universal','Single-phase fan','Switch off power; electrician installation recommended','capacitor, fan'],['Ceiling fan regulator','Home appliances','Fan','Universal','Selected AC fans','Not for DC fans; electrician fitting recommended','regulator, fan'],['Mixer grinder coupler','Home appliances','Mixer grinder','Preethi','Selected models','Match original coupler size','coupler, mixer'],['Air conditioner filter set','Home appliances','Air conditioner','Daikin','1.5 ton selected units','Verify indoor-unit model','filter, ac'],['AC remote control','Home appliances','Air conditioner','Universal','IR AC units','Verify supported model features','remote, ac'],['Motorcycle brake lever','Vehicles','Motorcycle','Honda','Activa 6G','Exact generation and side must match; professional fitting','brake, lever, scooter'],['Motorcycle chain sprocket kit','Vehicles','Motorcycle','Bajaj','Pulsar 150 selected years','Match year and variant; professional installation','chain, sprocket, bike'],['Car air filter','Vehicles','Car','Maruti Suzuki','Swift 2018–2022','Match engine and year','air filter, car'],['Car cabin filter','Vehicles','Car','Hyundai','i20 selected years','Check trim and year','cabin filter, car'],['Car wiper blade set','Vehicles','Car','Universal','Front set selected models','Measure blade lengths before buying','wiper, car'],['Car headlamp bulb H4','Vehicles','Car','Universal','H4 fitting only','Check vehicle manual and local road compliance','headlamp, bulb'],['Scooter mirror pair','Vehicles','Scooter','TVS','Jupiter selected models','Check thread and year','mirror, scooter'],['Water pump mechanical seal','Machinery','Water pump','Kirloskar','Selected 1HP pumps','Match dimensions; professional fitting recommended','seal, pump'],['Water pump capacitor','Machinery','Water pump','Universal','Selected single-phase motors','Voltage and capacitance must match; electrician only','capacitor, pump'],['Generator air filter','Machinery','Generator','Honda','EU22i selected versions','Confirm serial/model compatibility','filter, generator'],['Generator spark plug','Machinery','Generator','Universal','Check engine manual','Use only the specified plug type','spark plug, generator'],['Industrial pump bearing','Machinery','Industrial pump','Universal','6204 selected assemblies','Match bearing code and shaft size','bearing, pump'],['Generator fuel filter','Machinery','Generator','Honda','Selected portable generators','Fuel system work should be handled by a professional','fuel filter, generator'],['Workshop compressor belt','Machinery','Air compressor','Universal','Measure pulley and belt section','Isolate equipment; professional fitting recommended','belt, compressor'],['Motorcycle oil filter','Vehicles','Motorcycle','Royal Enfield','Classic 350 selected years','Verify generation and engine','oil filter, bike'],['Laptop hinge set','Electronics','Laptop','Lenovo','IdeaPad 3 selected models','Confirm exact MTM/model number','hinge, laptop'],['Refrigerator shelf rail','Home appliances','Refrigerator','Samsung','Selected top-freezer models','Measure rail and confirm model','shelf, fridge'],['Car battery terminal clamp','Vehicles','Car','Universal','12V automotive battery','Professional installation advised','battery, terminal, car']
];
function bootstrap() {
  if (bootstrapPromise) return bootstrapPromise;
  bootstrapPromise = (async () => {
  await mongo.connect(); db = mongo.db(DB_NAME); bucket = new GridFSBucket(db, { bucketName: 'uploads' });
  await Promise.all([db.collection('users').createIndex({ email: 1 }, { unique: true }), db.collection('sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }), db.collection('requests').createIndex({ customerId: 1, createdAt: -1 }), db.collection('requests').createIndex({ professionalId: 1, status: 1 }), db.collection('listings').createIndex({ status: 1, createdAt: -1 }), db.collection('listings').createIndex({ seedKey: 1 }, { unique: true, sparse: true }), db.collection('parts').createIndex({ partNumber: 1 }, { unique: true }), db.collection('parts').createIndex({ name: 'text', brand: 'text', model: 'text', productType: 'text', compatibility: 'text', partNumber: 'text', keywords: 'text' }), db.collection('orders').createIndex({ buyerId: 1, createdAt: -1 })]);
  if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) { const email = emailNorm(process.env.ADMIN_EMAIL); await db.collection('users').updateOne({ email }, { $setOnInsert: { name: 'FixBridge Administrator', email, passwordHash: await bcrypt.hash(process.env.ADMIN_PASSWORD, 12), role: 'admin', approved: true, disabled: false, createdAt: new Date() } }, { upsert: true }); }
  const parts = db.collection('parts');
  await Promise.all(baseParts.map(([name,category,productType,brand,model,compatibility,keywords],i) => { const partNumber = `FB-${String(i+1).padStart(4,'0')}`; return parts.updateOne({ partNumber }, { $setOnInsert: { name,category,productType,brand,model,compatibility,keywords,partNumber,price:350+((i*389)%7800),stock:4+(i%25),deliveryEstimate:'3–5 days (sample)',returns:'7 days unopened, subject to seller terms',active:true,createdAt:new Date() } }, { upsert: true }); }));
  const sampleListings = [{seedKey:'demo-macbook',title:'MacBook Air M1',category:'Electronics',brand:'Apple',model:'MacBook Air M1',year:'2021',condition:'Good',description:'Well cared for, reset and ready to use.',price:42000,location:'Koramangala, Bengaluru',sellerName:'Sample seller',status:'Available',createdAt:new Date()},{seedKey:'demo-activa',title:'Honda Activa 6G',category:'Vehicles',brand:'Honda',model:'Activa 6G',year:'2022',condition:'Very good',description:'Regularly serviced, used for short commutes.',price:68000,location:'HSR Layout, Bengaluru',sellerName:'Sample seller',status:'Available',createdAt:new Date()},{seedKey:'demo-washer',title:'Front-load washing machine',category:'Home appliances',brand:'LG',model:'7 kg front load',year:'2020',condition:'Good',description:'Works well, sample marketplace item.',price:12500,location:'Jayanagar, Bengaluru',sellerName:'Sample seller',status:'Available',createdAt:new Date()}];
  if (await db.collection('listings').estimatedDocumentCount() === 0) await Promise.all(sampleListings.map(listing => db.collection('listings').updateOne({ seedKey: listing.seedKey }, { $setOnInsert: listing }, { upsert: true })));
  })().catch(error => { bootstrapPromise = null; throw error; });
  return bootstrapPromise;
}
module.exports = app;
if (!process.env.NETLIFY && !process.env.AWS_LAMBDA_FUNCTION_NAME) bootstrap().then(() => app.listen(PORT, () => console.log(`FixBridge running at http://localhost:${PORT} (MongoDB database: ${DB_NAME})`))).catch(error => { console.error('Startup failed:', error.message); process.exit(1); });
