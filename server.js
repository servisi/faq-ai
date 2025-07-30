// server.js  (ÜCRETSİZ – sadece free plan)
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const OpenAI = require('openai');
const axios = require('axios');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const basicAuth = require('basic-auth');

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors({ origin: '*', methods: ['GET', 'POST'], allowedHeaders: ['Content-Type', 'Authorization'] }));

// Rate-limit: 1 dk içinde max 10 istek
const limiter = rateLimit({ windowMs: 60 * 1000, max: 10, message: 'Too many requests' });
app.use('/api/generate-faq', limiter);

mongoose.connect(process.env.MONGO_URI);

// Kullanıcı şeması – yalnızca free
const UserSchema = new mongoose.Schema({
  email: String,
  phone: String,
  site: String,
  credits: { type: Number, default: 20 },
  lastReset: { type: Date, default: Date.now },
  plan: { type: String, default: 'free' },
  createdAt: { type: Date, default: Date.now },
  deletedAt: Date
});
const User = mongoose.model('User', UserSchema);

// Önbellek şeması (7 gün)
const FaqCacheSchema = new mongoose.Schema({
  title: String,
  language: String,
  num_questions: Number,
  faqs: Array,
  createdAt: { type: Date, default: Date.now, expires: '7d' }
});
const FaqCache = mongoose.model('FaqCache', FaqCacheSchema);

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const JWT_SECRET = process.env.JWT_SECRET;
const SERPER_API_KEY = process.env.SERPER_API_KEY;
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;

function adminAuth(req, res, next) {
  const user = basicAuth(req);
  if (!user || user.name !== ADMIN_USER || user.pass !== ADMIN_PASS) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin"');
    return res.status(401).send('Unauthorized');
  }
  next();
}

function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.userId = jwt.verify(token, JWT_SECRET).userId;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Aylık kredi reset – yalnızca free (20 kredi)
async function resetCreditsIfNeeded(user) {
  const now = new Date();
  if (now.getMonth() !== user.lastReset.getMonth() || now.getFullYear() !== user.lastReset.getFullYear()) {
    user.credits = 20;
    user.lastReset = now;
    await user.save();
  }
}

// Plugin versiyon (ücretsiz)
const PluginVersionSchema = new mongoose.Schema({
  plugin_name: { type: String, default: 'sss-ai' },
  version: { type: String, default: '3.1' },
  tested: { type: String, default: '6.8' },
  last_updated: { type: Date, default: Date.now },
  download_url: { type: String, default: 'https://github.com/servisi/faq-ai/releases/download/sss-ai.zip' },
  description: { type: String, default: 'Sayfa başlığına göre Yapay Zeka ile güncel SSS üretir ve ekler.' },
  changelog: { type: String, default: '<h4>Versiyon 3.1</h4><ul><li>Performans iyileştirmeleri</li></ul>' }
});
const PluginVersion = mongoose.model('PluginVersion', PluginVersionSchema);

async function getPluginVersion() {
  let v = await PluginVersion.findOne({ plugin_name: 'sss-ai' });
  if (!v) {
    v = new PluginVersion({});
    await v.save();
  }
  return v;
}

app.get('/wp-update-check', async (req, res) => {
  if (req.query.action === 'get_version' && req.query.plugin === 'sss-ai') {
    const p = await getPluginVersion();
    res.json({
      version: p.version,
      tested: p.tested,
      last_updated: p.last_updated.toISOString().split('T')[0],
      download_url: p.download_url,
      description: p.description,
      changelog: p.changelog
    });
  } else {
    res.status(404).json({ error: 'Invalid request' });
  }
});

app.get('/download/sss-ai.zip', (req, res) => res.redirect('https://github.com/servisi/faq-ai/releases/download/sss-ai.zip'));

// Kullanıcı kaydı (ücretsiz)
app.post('/register', async (req, res) => {
  const { email, phone, site } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  let user = await User.findOne({ email });
  if (user) {
    if (phone) user.phone = phone;
    if (site) user.site = site;
    if (user.deletedAt) user.deletedAt = null;
    await user.save();
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ token });
  }

  user = new User({ email, phone, site });
  await user.save();
  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token });
});

// Ücretsiz – Kullanıcı bilgisi
app.get('/user-info', authenticate, async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.deletedAt) return res.status(401).json({ error: 'Account deleted' });
  await resetCreditsIfNeeded(user);
  res.json({
    plan: 'Ücretsiz',
    credits: user.credits
  });
});

// FAQ üret – yalnızca 5 soru
app.post('/api/generate-faq', authenticate, async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user || user.deletedAt) return res.status(401).json({ error: 'User not found' });

  await resetCreditsIfNeeded(user);

  let { title, language = 'tr', force = false } = req.body;
  const num_questions = 5;

  const cacheKey = { title, language, num_questions };
  const cached = await FaqCache.findOne(cacheKey);
  if (cached && !force) return res.json({ faqs: cached.faqs, cached: true });

  const cost = 1; // 5 soru = 1 kredi
  if (user.credits < cost) return res.status(400).json({ error: 'no_credits' });

  // (Serper + OpenAI prompt kısaltıldı – ücretsizde gerekli minimum)
  let recentNews = '';
  try {
    const r = await axios.post('https://google.serper.dev/search', { q: `${title} son haberler`, num: 3, tbs: 'qdr:w', hl: 'tr', gl: 'tr' }, { headers: { 'X-API-KEY': SERPER_API_KEY }, timeout: 15000 });
    recentNews = (r.data.organic || []).map(o => `${o.title}: ${o.snippet}`).join('\n');
  } catch {
    recentNews = 'Güncel haberler tespit edilemedi.';
  }

  const prompt = `Başlık: ${title}. ${recentNews}. En çok aranan 5 FAQ sorusu ve kısa cevapları. JSON: {"faqs":[{"question":"...","answer":"..."}]}`;

  try {
    const completion = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      response_format: { type: 'json_object' }
    });
    const faqs = JSON.parse(completion.choices[0].message.content).faqs;
    if (faqs.length !== 5) throw new Error('Count mismatch');

    user.credits -= cost;
    await user.save();
    await FaqCache.findOneAndUpdate(cacheKey, { ...cacheKey, faqs }, { upsert: true, new: true });

    res.json({ faqs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin paneli (ücretsizde sadece kullanıcı listesi)
app.get('/admin/users', adminAuth, async (req, res) => {
  const { search } = req.query;
  const q = search ? { email: { $regex: search, $options: 'i' } } : {};
  const users = await User.find(q, 'email phone site credits createdAt');
  res.json(users);
});

// Admin panel HTML (ücretsiz)
app.get('/admin', adminAuth, (req, res) => res.send(`
<!doctype html><title>Admin – Ücretsiz</title>
<h2>Ücretsiz Kullanıcılar</h2>
<table border="1" cellpadding="6"><thead><tr><th>Email</th><th>Telefon</th><th>Site</th><th>Kredi</th><th>Oluşturulma</th></tr></thead><tbody id="tbody"></tbody></table>
<script>
fetch('/admin/users').then(r=>r.json()).then(u=>{
 tbody.innerHTML=u.map(x=>"<tr><td>"+x.email+"</td><td>"+(x.phone||"")+"</td><td>"+(x.site||"")+"</td><td>"+x.credits+"</td><td>"+new Date(x.createdAt).toLocaleDateString()+"</td></tr>").join("");
});
</script>
`));

module.exports = app;
