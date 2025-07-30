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
const fs = require('fs');
const path = require('path');

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: 'Too many requests, please try again later.'
});
app.use('/api/generate-faq', limiter);

// Vercel uyumlu MongoDB bağlantısı
let conn = null;
async function dbConnect() {
  if (conn == null) {
    conn = await mongoose.connect(process.env.MONGO_URI, {
      bufferCommands: false,
      bufferMaxEntries: 0
    });
    conn = mongoose.connection;
  }
  return conn;
}

const UserSchema = new mongoose.Schema({
  email: String,
  credits: { type: Number, default: 20 },
  lastReset: { type: Date, default: Date.now },
  plan: { type: String, default: 'free' },
  expirationDate: { type: Date, default: null }
});
const User = mongoose.model('User', UserSchema);

const openai = new OpenAI({ 
  apiKey: process.env.OPENAI_API_KEY,
});
const JWT_SECRET = process.env.JWT_SECRET;
const SERPER_API_KEY = process.env.SERPER_API_KEY;
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;

// Basic Auth Middleware for Admin
function adminAuth(req, res, next) {
  const user = basicAuth(req);
  if (!user || user.name !== ADMIN_USER || user.pass !== ADMIN_PASS) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin"');
    return res.status(401).send('Unauthorized');
  }
  next();
}

// Middleware: Token Doğrula
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

// Helper: Pro Expiration Kontrolü ve Downgrade
async function checkProExpiration(user) {
  const now = new Date();
  if (user.plan === 'pro' && user.expirationDate && user.expirationDate < now) {
    user.plan = 'free';
    user.credits = 20;
    user.lastReset = now;
    user.expirationDate = null;
    await user.save();
  }
}

// Helper: Aylık Reset Kontrolü
async function resetCreditsIfNeeded(user) {
  const now = new Date();
  if (now.getMonth() !== user.lastReset.getMonth() || now.getFullYear() !== user.lastReset.getFullYear()) {
    user.credits = user.plan === 'pro' ? 120 : 20;
    user.lastReset = now;
    await user.save();
  }
}

// === WORDPRESS GÜNCELLEME ENDPOİNTLERİ === //

// Plugin Version Schema
const PluginVersionSchema = new mongoose.Schema({
  plugin_name: { type: String, default: 'sss-ai' },
  version: { type: String, default: '3.0' },
  tested: { type: String, default: '6.8' },
  last_updated: { type: Date, default: Date.now },
  download_url: { type: String, default: 'https://github.com/servisi/faq-ai/releases/download/v3.0/sss-ai.zip' },
  description: { type: String, default: 'Sayfa başlığına göre Yapay Zeka ile güncel SSS üretir ve ekler.' },
  changelog: { type: String, default: '<h4>Versiyon 3.0</h4><ul><li>Güncelleme sırasında oluşan hata çözüldü.</li></ul>' }
});
const PluginVersion = mongoose.model('PluginVersion', PluginVersionSchema);

// Plugin versiyon bilgisini database'den al
async function getPluginVersion() {
  await dbConnect(); // <-- eklendi
  try {
    let version = await PluginVersion.findOne({ plugin_name: 'sss-ai' });
    if (!version) {
      version = new PluginVersion({
        plugin_name: 'sss-ai',
        version: '3.0',
        tested: '6.8',
        download_url: 'https://github.com/servisi/faq-ai/releases/download/v3.0/sss-ai.zip',
        description: 'Sayfa başlığına göre Yapay Zeka ile güncel SSS üretir ve ekler. Kredi tabanlı sistem.',
        changelog: `
          <h4>Versiyon 3.0</h4>
    <ul>
      <li>Güncelleme sırasında oluşan hata çözüldü.</li>
    </ul>
        `
      });
      await version.save();
    }
    return version;
  } catch (error) {
    console.error('Plugin version fetch error:', error);
    return {
      version: '3.0',
      tested: '6.8',
      last_updated: new Date().toISOString().split('T')[0],
      download_url: 'https://github.com/servisi/faq-ai/releases/download/v3.0/sss-ai.zip',
      description: 'Sayfa başlığına göre Yapay Zeka ile güncel SSS üretir ve ekler.',
      changelog: '<h4>Versiyon 2.8</h4><ul><li>Otomatik güncelleme sistemi</li></ul>'
    };
  }
}

// WordPress güncelleme kontrolü endpoint'i
app.get('/wp-update-check', async (req, res) => {
  const { action, plugin } = req.query;
  if (action === 'get_version' && plugin === 'sss-ai') {
    const pluginVersion = await getPluginVersion();
    res.json({
      version: pluginVersion.version,
      tested: pluginVersion.tested,
      last_updated: pluginVersion.last_updated instanceof Date ? 
        pluginVersion.last_updated.toISOString().split('T')[0] : 
        pluginVersion.last_updated,
      download_url: pluginVersion.download_url,
      description: pluginVersion.description,
      changelog: pluginVersion.changelog
    });
  } else {
    res.status(404).json({ error: 'Invalid request' });
  }
});

// Plugin dosyası indirme endpoint'i
app.get('/download/sss-ai-v2.8.zip', (req, res) => {
  res.redirect('https://github.com/servisi/faq-ai/releases/download/v3.0/sss-ai.zip');
});

// Admin-only download endpoint
app.get('/admin/download/sss-ai-v3.0.zip', adminAuth, (req, res) => {
  res.json({
    message: 'Admin plugin download would be served here',
    note: 'Bu endpoint admin için özel indirme linki'
  });
});

// Plugin changelog endpoint'i
app.get('/changelog/sss-ai', async (req, res) => {
  const pluginVersion = await getPluginVersion();
  res.json({
    plugin: 'SSS Oluşturucu',
    current_version: pluginVersion.version,
    changelog: pluginVersion.changelog,
    download_structure: 'sss-ai/sss-ai.php',
    important_note: 'ZIP dosyası içinde klasör adı "sss-ai" olmalı, başka bir ad OLMAMALI!'
  });
});

// === MEVCUT ENDPOİNTLER === //

// Kayıt Endpoint
app.post('/register', async (req, res) => {
  await dbConnect(); // <-- eklendi
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  let user = await User.findOne({ email });
  if (user) {
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ token });
  }
  user = new User({ email });
  await user.save();
  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token });
});

// User Info Endpoint
app.get('/user-info', authenticate, async (req, res) => {
  await dbConnect(); // <-- eklendi
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  await checkProExpiration(user);
  await resetCreditsIfNeeded(user);

  const now = new Date();
  let remainingDays = 0;
  if (user.plan === 'pro' && user.expirationDate) {
    remainingDays = Math.max(0, Math.ceil((user.expirationDate - now) / (1000 * 60 * 60 * 24)));
  }

  res.json({
    plan: user.plan === 'free' ? 'Ücretsiz Sürüm' : 'Pro Sürüm',
    credits: user.credits,
    remainingDays: remainingDays
  });
});

// FAQ Üret Endpoint
app.post('/api/generate-faq', authenticate, async (req, res) => {
  await dbConnect(); // <-- eklendi
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  await checkProExpiration(user);
  await resetCreditsIfNeeded(user);

  if (user.credits <= 0) {
    return res.status(402).json({ error: 'no_credits' });
  }

  const { title, num_questions, language = 'tr' } = req.body;

  let recentNews = '';
  let searchQuerySuffix = language === 'tr' ? 'son haberler' : 'latest news';
  let serperHl = language;
  let serperGl = language === 'tr' ? 'tr' : 'us';

  try {
    const searchResponse = await axios.post('https://google.serper.dev/search', {
      q: `${title} ${searchQuerySuffix}`,
      num: 5,
      tbs: 'qdr:w',
      hl: serperHl,
      gl: serperGl
    }, {
      headers: {
        'X-API-KEY': SERPER_API_KEY,
        'Content-Type': 'application/json'
      }
    });
    const results = searchResponse.data.organic || [];
    recentNews = results.map(result => `${result.title}: ${result.snippet} (Kaynak: ${result.link})`).join('\n');
  } catch (searchErr) {
    console.error('Search error:', searchErr);
    recentNews = language === 'tr' ? 'Güncel haberler tespit edilemedi.' : 'Recent news could not be detected.';
  }

  let prompt;
  if (language === 'tr') {
    prompt = `Başlık: ${title}. Son güncel haberler ve bilgiler: ${recentNews}. Bu güncel bilgilerle en çok aranan ${num_questions} FAQ sorusu üret ve her birine kısa, bilgilendirici cevap ver. Yanıtı JSON formatında ver: {"faqs": [{"question": "Soru", "answer": "Cevap"}]}`;
  } else {
    prompt = `Title: ${title}. Recent news and information: ${recentNews}. Based on this current information, generate the top ${num_questions} FAQ questions and provide short, informative answers for each. Respond in JSON format: {"faqs": [{"question": "Question", "answer": "Answer"}]}`;
  }

  try {
    const completion = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      response_format: { type: "json_object" }
    });
    let content = completion.choices[0].message.content;
    let faqs;
    try {
      faqs = JSON.parse(content).faqs;
    } catch (parseErr) {
      console.error('JSON parse error:', parseErr, content);
      return res.status(500).json({ error: 'AI response parse failed' });
    }

    user.credits -= 1;
    await user.save();

    res.json({ faqs });
  } catch (err) {
    console.error('OpenAI error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Admin Users Endpoint
app.get('/admin/users', adminAuth, async (req, res) => {
  await dbConnect(); // <-- eklendi
  const { search, plan } = req.query;
  let query = {};
  if (plan && plan !== 'all') query.plan = plan;
  if (search) query.email = { $regex: search, $options: 'i' };
  const users = await User.find(query, 'email plan credits expirationDate lastReset');
  res.json(users);
});

// Admin Update User Endpoint
app.post('/admin/update-user', adminAuth, async (req, res) => {
  await dbConnect(); // <-- eklendi
  const { userId, plan, credits, expirationDate } = req.body;
  const user = await User.findById(userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (plan) user.plan = plan;
  if (credits !== undefined) user.credits = credits;
  if (expirationDate) user.expirationDate = new Date(expirationDate);
  await user.save();

  res.json({ success: true });
});

// Plugin istatistikleri endpoint'i (admin)
app.get('/admin/plugin-stats', adminAuth, async (req, res) => {
  await dbConnect(); // <-- eklendi
  try {
    const totalUsers = await User.countDocuments();
    const freeUsers = await User.countDocuments({ plan: 'free' });
    const proUsers = await User.countDocuments({ plan: 'pro' });
    const activeUsers = await User.countDocuments({ credits: { $gt: 0 } });
    const pluginVersion = await getPluginVersion();

    res.json({
      total_users: totalUsers,
      free_users: freeUsers,
      pro_users: proUsers,
      active_users: activeUsers,
      plugin_version: pluginVersion.version,
      last_updated: pluginVersion.last_updated instanceof Date ? 
        pluginVersion.last_updated.toISOString().split('T')[0] : 
        pluginVersion.last_updated
    });
  } catch (error) {
    res.status(500).json({ error: 'Statistics fetch failed', details: error.message });
  }
});

// Plugin versiyonunu güncelleme endpoint'i (admin only)
app.post('/admin/update-plugin-version', adminAuth, async (req, res) => {
  await dbConnect(); // <-- eklendi
  const { version, tested, description, changelog, download_url } = req.body;
  
  if (!version) {
    return res.status(400).json({ error: 'Version is required' });
  }

  try {
    let pluginVersion = await PluginVersion.findOne({ plugin_name: 'sss-ai' });
    if (!pluginVersion) {
      pluginVersion = new PluginVersion({ plugin_name: 'sss-ai' });
    }

    if (version) pluginVersion.version = version;
    if (tested) pluginVersion.tested = tested;
    if (description) pluginVersion.description = description;
    if (changelog) pluginVersion.changelog = changelog;
    if (download_url) pluginVersion.download_url = download_url;
    
    pluginVersion.last_updated = new Date();
    await pluginVersion.save();

    res.json({
      success: true,
      message: 'Plugin version updated successfully in database',
      updated_version: {
        version: pluginVersion.version,
        tested: pluginVersion.tested,
        last_updated: pluginVersion.last_updated.toISOString().split('T')[0],
        download_url: pluginVersion.download_url,
        description: pluginVersion.description,
        changelog: pluginVersion.changelog
      }
    });
  } catch (error) {
    console.error('Plugin version update error:', error);
    res.status(500).json({ 
      error: 'Database update failed', 
      details: error.message 
    });
  }
});

// Admin Panel HTML Page (değişmedi)
app.get('/admin', adminAuth, (req, res) => {
  res.send(`... (aynı HTML) ...`);
});

// Vercel için export
module.exports = app;
