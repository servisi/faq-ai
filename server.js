// server.js
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

// Rate limiting
const limiter = rateLimit({ windowMs: 60 * 1000, max: 10, message: 'Too many requests.' });
app.use('/api/generate-faq', limiter);

mongoose.connect(process.env.MONGO_URI);

// Kullanıcı şeması (pro/agency kaldırıldı)
const UserSchema = new mongoose.Schema({
  email: String,
  credits: { type: Number, default: 20 },
  lastReset: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
  deletedAt: { type: Date, default: null }
});
const User = mongoose.model('User', UserSchema);

// Önbellek şeması
const FaqCacheSchema = new mongoose.Schema({
  title: String,
  language: String,
  faqs: Array,
  createdAt: { type: Date, default: Date.now, expires: '7d' }
});
const FaqCache = mongoose.model('FaqCache', FaqCacheSchema);

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const JWT_SECRET = process.env.JWT_SECRET;
const SERPER_API_KEY = process.env.SERPER_API_KEY;
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;

// Basic Auth Middleware
function adminAuth(req, res, next) {
  const user = basicAuth(req);
  if (!user || user.name !== ADMIN_USER || user.pass !== ADMIN_PASS) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin"');
    return res.status(401).send('Unauthorized');
  }
  next();
}

// Token Doğrula
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Aylık Reset Kontrolü (sabit 20 kredi)
async function resetCreditsIfNeeded(user) {
  const now = new Date();
  if (now.getMonth() !== user.lastReset.getMonth() || now.getFullYear() !== user.lastReset.getFullYear()) {
    user.credits = 20;
    user.lastReset = now;
    await user.save();
  }
}

// Plugin Version Schema (korundu)
const PluginVersionSchema = new mongoose.Schema({
  plugin_name: { type: String, default: 'sss-ai' },
  version: { type: String, default: '3.0' },
  tested: { type: String, default: '6.8' },
  last_updated: { type: Date, default: Date.now },
  download_url: { type: String, default: 'https://github.com/servisi/faq-ai/releases/download/sss-ai.zip' },
  description: { type: String, default: 'Sayfa başlığına göre Yapay Zeka ile güncel SSS üretir ve ekler.' }
});
const PluginVersion = mongoose.model('PluginVersion', PluginVersionSchema);

async function getPluginVersion() {
  let version = await PluginVersion.findOne({ plugin_name: 'sss-ai' });
  if (!version) {
    version = new PluginVersion();
    await version.save();
  }
  return version;
}

// WordPress güncelleme endpoint'leri (sade)
app.get('/wp-update-check', async (req, res) => {
  const { action, plugin } = req.query;
  if (action === 'get_version' && plugin === 'sss-ai') {
    const pluginVersion = await getPluginVersion();
    res.json({
      version: pluginVersion.version,
      tested: pluginVersion.tested,
      last_updated: pluginVersion.last_updated.toISOString().split('T')[0],
      download_url: pluginVersion.download_url,
      description: pluginVersion.description
    });
  } else {
    res.status(404).json({ error: 'Invalid request' });
  }
});

// Kayıt Endpoint
app.post('/register', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  let user = await User.findOne({ email });
  if (user) {
    if (user.deletedAt) user.deletedAt = null;
    await user.save();
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ token });
  }
  user = new User({ email });
  await user.save();
  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token });
});

// User Info Endpoint (pro'suz)
app.get('/user-info', authenticate, async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user || user.deletedAt) return res.status(404).json({ error: 'User not found' });
  await resetCreditsIfNeeded(user);
  res.json({ credits: user.credits });
});

// FAQ Üret Endpoint (sabit 5 soru, short)
app.post('/api/generate-faq', authenticate, async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user || user.deletedAt) return res.status(404).json({ error: 'User not found' });
  await resetCreditsIfNeeded(user);
  const { title, language = 'tr' } = req.body;
  const num_questions = 5;
  const required_credits = 1; // Sabit 1 kredi
  if (user.credits < required_credits) return res.status(400).json({ error: 'no_credits' });

  const cacheKey = { title, language };
  const cachedFaq = await FaqCache.findOne(cacheKey);
  if (cachedFaq) return res.json({ faqs: cachedFaq.faqs, cached: true });

  let recentNews = '';
  try {
    const searchResponse = await axios.post('https://google.serper.dev/search', {
      q: `${title} ${language === 'tr' ? 'son haberler' : 'latest news'}`,
      num: 5,
      tbs: 'qdr:w',
      hl: language,
      gl: language === 'tr' ? 'tr' : 'us'
    }, { headers: { 'X-API-KEY': SERPER_API_KEY, 'Content-Type': 'application/json' }, timeout: 15000 });
    const results = searchResponse.data.organic || [];
    recentNews = results.map(result => `${result.title}: ${result.snippet}`).join('\n');
  } catch (err) {
    recentNews = 'Güncel haberler tespit edilemedi.';
  }

  const prompt = language === 'tr' ? 
    `Başlık: ${title}. Güncel bilgiler: ${recentNews}. En çok aranan 5 FAQ sorusu üret ve her birine kısa cevap ver. JSON: {"faqs": [{"question": "Soru", "answer": "Cevap"}]}` :
    `Title: ${title}. Recent info: ${recentNews}. Generate top 5 FAQ questions with short answers. JSON: {"faqs": [{"question": "Question", "answer": "Answer"}]}`;

  try {
    const completion = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      response_format: { type: "json_object" }
    });
    const faqs = JSON.parse(completion.choices[0].message.content).faqs;

    user.credits -= required_credits;
    await user.save();
    await FaqCache.create({ ...cacheKey, faqs });

    res.json({ faqs });
  } catch (err) {
    res.status(500).json({ error: 'AI error' });
  }
});

// Admin Users Endpoint (sade)
app.get('/admin/users', adminAuth, async (req, res) => {
  const { search } = req.query;
  let query = {};
  if (search) query.email = { $regex: search, $options: 'i' };
  const users = await User.find(query, 'email credits createdAt deletedAt');
  res.json(users);
});

// Admin Stats Endpoint (sade)
app.get('/admin/plugin-stats', adminAuth, async (req, res) => {
  const totalUsers = await User.countDocuments();
  res.json({ total_users: totalUsers });
});

// Admin Panel HTML (sadeleştirilmiş)
app.get('/admin', adminAuth, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="tr">
    <head><title>Admin Panel</title></head>
    <body>
      <h1>AI FAQ Admin</h1>
      <input type="text" id="searchInput" placeholder="Email ara">
      <button onclick="loadUsers()">Ara</button>
      <table id="usersTable"><thead><tr><th>Email</th><th>Credits</th><th>Oluşturulma</th><th>Silinme</th></tr></thead><tbody></tbody></table>
      <script>
        async function loadUsers() {
          const search = document.getElementById('searchInput').value;
          const response = await fetch('/admin/users?search=' + search);
          const users = await response.json();
          const tbody = document.querySelector('#usersTable tbody');
          tbody.innerHTML = '';
          users.forEach(user => {
            const tr = document.createElement('tr');
            tr.innerHTML = '<td>' + user.email + '</td><td>' + user.credits + '</td><td>' + new Date(user.createdAt).toLocaleDateString() + '</td><td>' + (user.deletedAt ? new Date(user.deletedAt).toLocaleDateString() : 'Aktif') + '</td>';
            tbody.appendChild(tr);
          });
        }
        loadUsers();
      </script>
    </body>
    </html>
  `);
});

// Vercel için export
module.exports = app;
