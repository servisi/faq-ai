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

mongoose.connect(process.env.MONGO_URI);

const UserSchema = new mongoose.Schema({
  email: String,
  phone: String,
  site: String,
  credits: { type: Number, default: 20 },
  lastReset: { type: Date, default: Date.now },
  plan: { type: String, default: 'free' },
  expirationDate: { type: Date, default: null },
  registrationDate: { type: Date, default: Date.now },
  active: { type: Boolean, default: true }
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

// Plugin Version Schema
const PluginVersionSchema = new mongoose.Schema({
  plugin_name: { type: String, default: 'sss-ai' },
  version: { type: String, default: '3.1' },
  tested: { type: String, default: '6.8' },
  last_updated: { type: Date, default: Date.now },
  download_url: { type: String, default: 'https://github.com/servisi/faq-ai/releases/latest/download/sss-ai.zip' },
  description: { type: String, default: 'Sayfa başlığına göre Yapay Zeka ile güncel SSS üretir ve ekler.' },
  changelog: { type: String, default: '<h4>Versiyon 3.1</h4><ul><li>Güncelleme sırasında oluşan hata çözüldü.</li></ul>' }
});
const PluginVersion = mongoose.model('PluginVersion', PluginVersionSchema);

const AnnouncementSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  date: { type: Date, default: Date.now },
  active: { type: Boolean, default: true }
});
const Announcement = mongoose.model('Announcement', AnnouncementSchema);

async function getPluginVersion() {
  try {
    let version = await PluginVersion.findOne({ plugin_name: 'sss-ai' });
    if (!version) {
      version = new PluginVersion({
        plugin_name: 'sss-ai',
        version: '3.0',
        tested: '6.8',
        download_url: 'https://github.com/servisi/faq-ai/releases/latest/download/sss-ai.zip',
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
      download_url: 'https://github.com/servisi/faq-ai/releases/latest/download/sss-ai.zip',
      description: 'Sayfa başlığına göre Yapay Zeka ile güncel SSS üretir ve ekler.',
      changelog: '<h4>Versiyon 3.0</h4><ul><li>Güncelleme sırasında oluşan hata çözüldü.</li></ul>'
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
app.get('/download/sss-ai-v3.1.zip', (req, res) => {
  res.redirect('https://github.com/servisi/faq-ai/releases/latest/download/sss-ai.zip');
});

// Plugin changelog endpoint'i
app.get('/changelog/sss-ai', async (req, res) => {
  const pluginVersion = await getPluginVersion();
  res.json({
    plugin: 'SSS Oluşturucu',
    current_version: pluginVersion.version,
    changelog: pluginVersion.changelog,
    download_structure: 'sss-ai/sss-ai.php',
    important_note: 'ZIP dosyası içinde klasör adı "sss-ai" olmalıdır!'
  });
});

// Kayıt Endpoint
app.post('/register', async (req, res) => {
  const { email, phone, site } = req.body;
  if (!email || !phone) return res.status(400).json({ error: 'Email ve telefon gereklidir' });
  
  let user = await User.findOne({ email });
  if (user) {
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ token });
  }
  
  user = new User({ 
    email, 
    phone,
    site,
    registrationDate: new Date()
  });
  
  await user.save();
  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token });
});

// User Info Endpoint
app.get('/user-info', authenticate, async (req, res) => {
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
    email: user.email,
    phone: user.phone,
    site: user.site,
    plan: user.plan === 'free' ? 'Ücretsiz Sürüm' : 'Pro Sürüm',
    credits: user.credits,
    remainingDays: remainingDays,
    createdAt: user.registrationDate
  });
});

// FAQ Üret Endpoint
app.post('/api/generate-faq', authenticate, async (req, res) => {
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
    prompt = `Başlık: ${title}. Son güncel bilgiler: ${recentNews}. Bu güncel bilgilerle en çok aranan ${num_questions} FAQ sorusu üret ve her birine kısa, bilgilendirici cevap ver. Kişisel bilgiler, rezervasyon, iptal randevu gibi canlı bilgiler, Politik, dini, finansal, tıbbi gibi hassas bilgilerden kaçın. Yanıltıcı, kesinliği olmayan bilgiler verme. Cevabı Google snipet üzerinde çıkabilecek şekilde yapılandır. Yanıtı JSON formatında ver: {"faqs": [{"question": "Soru", "answer": "Cevap"}]}`;
  } else {
    prompt = `Title: ${title}. Recent information: ${recentNews}. Based on this current information, generate the top ${num_questions} FAQ questions and provide short, informative answers for each. Avoid personal information, live information like reservations, canceled appointments, and sensitive information like political, religious, financial, and medical. Avoid providing misleading or inaccurate information. Structure your answer so it appears in the Google snippet. Respond in JSON format: {"faqs": [{"question": "Question", "answer": "Answer"}]}`;
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

// Hesap Silme Endpoint
app.post('/delete-account', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.active = false;
    await user.save();

    res.json({ success: true });
  } catch (error) {
    console.error('Account deletion error:', error);
    res.status(500).json({ error: 'Account deletion failed' });
  }
});

// Admin Users Endpoint
app.get('/admin/users', adminAuth, async (req, res) => {
  const { search, plan } = req.query;
  let query = {};
  if (plan && plan !== 'all') query.plan = plan;
  if (search) query.email = { $regex: search, $options: 'i' };
  const users = await User.find(query, 'email phone site plan credits expirationDate registrationDate active');
  res.json(users);
});

// Admin Update User Endpoint
app.post('/admin/update-user', adminAuth, async (req, res) => {
  const { userId, plan, credits, expirationDate } = req.body;
  const user = await User.findById(userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (plan) user.plan = plan;
  if (credits !== undefined) user.credits = credits;
  if (expirationDate) user.expirationDate = new Date(expirationDate);
  await user.save();

  res.json({ success: true });
});

// Plugin istatistikleri endpoint'i
app.get('/admin/plugin-stats', adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const freeUsers = await User.countDocuments({ plan: 'free' });
    const proUsers = await User.countDocuments({ plan: 'pro' });
    const activeUsers = await User.countDocuments({ credits: { $gt: 0 } });
    const inactiveUsers = await User.countDocuments({ active: false });
    const pluginVersion = await getPluginVersion();

    res.json({
      total_users: totalUsers,
      free_users: freeUsers,
      pro_users: proUsers,
      active_users: activeUsers,
      inactive_users: inactiveUsers,
      plugin_version: pluginVersion.version,
      last_updated: pluginVersion.last_updated instanceof Date ? 
        pluginVersion.last_updated.toISOString().split('T')[0] : 
        pluginVersion.last_updated
    });
  } catch (error) {
    res.status(500).json({ error: 'Statistics fetch failed', details: error.message });
  }
});

// Plugin versiyonunu güncelleme endpoint'i
app.post('/admin/update-plugin-version', adminAuth, async (req, res) => {
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

// Duyuruları listele (eklenti için, auth'suz veya token'la)
app.get('/announcements', async (req, res) => {
  const announcements = await Announcement.find({ active: true }).sort({ date: -1 });
  res.json(announcements);
});

// Admin endpoint'leri
app.get('/admin/announcements', adminAuth, async (req, res) => {
  const announcements = await Announcement.find().sort({ date: -1 });
  res.json(announcements);
});

app.get('/admin/announcements/:id', adminAuth, async (req, res) => {
  const ann = await Announcement.findById(req.params.id);
  if (!ann) return res.status(404).json({ error: 'Bulunamadı' });
  res.json(ann);
});

app.post('/admin/announcements', adminAuth, async (req, res) => {
  try {
    const ann = new Announcement(req.body);
    await ann.save();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/admin/announcements/:id', adminAuth, async (req, res) => {
  try {
    await Announcement.findByIdAndUpdate(req.params.id, req.body);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/admin/announcements/:id', adminAuth, async (req, res) => {
  try {
    await Announcement.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin Panel HTML Page (TAM DÜZELTMELİ)
app.get('/admin', adminAuth, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="tr">
    <head>
      <title>Admin Panel - AI FAQ Users & Plugin Management</title>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background-color: #f4f6f9;
          margin: 0;
          padding: 30px;
          color: #333;
          line-height: 1.6;
        }
        h1 {
          color: #007bff;
          margin-bottom: 30px;
          font-size: 2em;
          text-align: center;
        }
        
        /* Tab System */
        .tab-container {
          margin-bottom: 30px;
        }
        .tabs {
          display: flex;
          background-color: white;
          border-radius: 8px;
          overflow: hidden;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .tab {
          flex: 1;
          padding: 15px 20px;
          background-color: #f8f9fa;
          border: none;
          cursor: pointer;
          font-size: 16px;
          transition: background-color 0.3s;
        }
        .tab:hover {
          background-color: #e9ecef;
        }
        .tab.active {
          background-color: #007bff;
          color: white;
        }
        .tab-content {
          display: none;
        }
        .tab-content.active {
          display: block;
        }

        /* Plugin Stats Card */
        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 20px;
          margin-bottom: 30px;
        }
        .stat-card {
          background: white;
          padding: 20px;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          text-align: center;
        }
        .stat-number {
          font-size: 2em;
          font-weight: bold;
          color: #007bff;
        }
        .stat-label {
          color: #666;
          margin-top: 5px;
        }

        #controls {
          display: flex;
          flex-wrap: wrap;
          gap: 15px;
          margin-bottom: 30px;
          justify-content: center;
        }
        input, select {
          padding: 12px;
          border: 1px solid #ced4da;
          border-radius: 6px;
          flex: 1 1 200px;
          font-size: 1em;
          transition: border-color 0.3s;
        }
        input:focus, select:focus {
          border-color: #007bff;
          outline: none;
        }
        button {
          padding: 12px 20px;
          background-color: #007bff;
          color: white;
          border: none;
          border-radius: 6px;
          cursor: pointer;
          font-size: 1em;
          transition: background-color 0.3s, transform 0.2s;
        }
        button:hover {
          background-color: #0056b3;
          transform: translateY(-2px);
        }
        #stats {
          margin-bottom: 30px;
          padding: 15px;
          background-color: #e9ecef;
          border-radius: 8px;
          text-align: center;
          font-weight: bold;
          box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        table {
          width: 100%;
          border-collapse: separate;
          border-spacing: 0;
          background-color: white;
          border-radius: 8px;
          overflow: hidden;
          box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        th, td {
          padding: 15px;
          text-align: left;
          border-bottom: 1px solid #dee2e6;
        }
        th {
          background-color: #007bff;
          color: white;
          font-weight: bold;
        }
        tr:last-child td {
          border-bottom: none;
        }
        tr:hover {
          background-color: #f1f3f5;
        }
        td button {
          background-color: #28a745;
          padding: 8px 12px;
          font-size: 0.9em;
          border-radius: 4px;
        }
        td button:hover {
          background-color: #218838;
        }
        
        /* Plugin Management Form */
        .plugin-form {
          background: white;
          padding: 20px;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          margin-bottom: 20px;
        }
        .form-group {
          margin-bottom: 20px;
        }
        .form-group label {
          display: block;
          margin-bottom: 5px;
          font-weight: bold;
        }
        .form-group input, .form-group textarea {
          width: 100%;
          padding: 10px;
          border: 1px solid #ced4da;
          border-radius: 4px;
          box-sizing: border-box;
        }
        .form-group textarea {
          height: 120px;
          resize: vertical;
        }

        /* Modal Stilleri */
        .modal {
          display: none;
          position: fixed;
          z-index: 1000;
          left: 0;
          top: 0;
          width: 100%;
          height: 100%;
          background-color: rgba(0,0,0,0.5);
          justify-content: center;
          align-items: center;
        }
        .modal-content {
          background-color: white;
          padding: 30px;
          border-radius: 8px;
          width: 90%;
          max-width: 500px;
          box-shadow: 0 4px 20px rgba(0,0,0,0.2);
        }
        .modal-content h2 {
          margin-top: 0;
          color: #007bff;
        }
        .modal-content label {
          display: block;
          margin-bottom: 10px;
          font-weight: bold;
        }
        .modal-content input, .modal-content select {
          width: 100%;
          margin-bottom: 20px;
        }
        .modal-content button {
          width: 48%;
        }
        .modal-content .close-btn {
          background-color: #dc3545;
        }
        .modal-content .close-btn:hover {
          background-color: #c82333;
        }
        .modal-content .submit-btn {
          background-color: #28a745;
        }
        .modal-content .submit-btn:hover {
          background-color: #218838;
        }
        
        /* Responsive tasarım */
        @media (max-width: 768px) {
          #controls {
            flex-direction: column;
          }
          .modal-content {
            width: 95%;
          }
          .stats-grid {
            grid-template-columns: 1fr;
          }
        }
      </style>
    </head>
    <body>
      <h1>AI FAQ Admin Panel</h1>
      
      <!-- Tab Navigation -->
      <div class="tab-container">
        <div class="tabs">
          <button class="tab active" onclick="showTab('users')">Kullanıcı Yönetimi</button>
          <button class="tab" onclick="showTab('plugin')">Plugin Yönetimi</button>
          <button class="tab" onclick="showTab('stats')">İstatistikler</button>
          <button class="tab" onclick="showTab('announcements')">Duyurular Yönetimi</button>
        </div>
      </div>

      <!-- Users Tab -->
      <div id="users-tab" class="tab-content active">
        <h2>Kullanıcı Yönetimi</h2>
        <div id="controls">
          <input type="text" id="searchInput" placeholder="Email ile ara">
          <select id="planFilter">
            <option value="all">Tümü</option>
            <option value="free">Free</option>
            <option value="pro">Pro (Aktif)</option>
          </select>
          <button onclick="loadUsers()">Ara/Filtrele</button>
        </div>
        <div id="stats"></div>
        <table id="usersTable">
          <thead>
            <tr>
              <th>Email</th>
              <th>Telefon</th>
              <th>Site</th>
              <th>Plan</th>
              <th>Credits</th>
              <th>Son Geçerlilik</th>
              <th>Kayıt Tarihi</th>
              <th>Durum</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <!-- Plugin Management Tab -->
      <div id="plugin-tab" class="tab-content">
        <h2>Plugin Sürüm Yönetimi</h2>
        <div class="plugin-form">
          <form id="pluginVersionForm">
            <div class="form-group">
              <label for="pluginVersion">Plugin Versiyonu</label>
              <input type="text" id="pluginVersion" placeholder="örn: 3.0" required>
            </div>
            <div class="form-group">
              <label for="pluginTested">Test Edildiği WordPress Versiyonu</label>
              <input type="text" id="pluginTested" placeholder="örn: 6.8" required>
            </div>
            <div class="form-group">
              <label for="pluginDescription">Açıklama</label>
              <textarea id="pluginDescription" placeholder="Plugin açıklaması..."></textarea>
            </div>
            <div class="form-group">
              <label for="pluginChangelog">Changelog (HTML formatında)</label>
              <textarea id="pluginChangelog" placeholder="<h4>Versiyon X.X</h4><ul><li>Yeni özellik</li></ul>"></textarea>
            </div>
            <div class="form-group">
              <label for="pluginDownloadUrl">İndirme URL'si</label>
              <input type="url" id="pluginDownloadUrl" placeholder="https://example.com/plugin.zip">
            </div>
            <button type="submit">Plugin Versiyonunu Güncelle</button>
          </form>
        </div>
        <div id="pluginUpdateResult"></div>
      </div>

      <!-- Stats Tab -->
      <div id="stats-tab" class="tab-content">
        <h2>Genel İstatistikler</h2>
        <div class="stats-grid" id="statsGrid">
          <!-- Stats will be loaded here -->
        </div>
      </div>

      <!-- Announcements Tab -->
      <div id="announcements-tab" class="tab-content">
        <h2>Duyurular Yönetimi</h2>
        <div class="plugin-form">
          <form id="announcementForm">
            <div class="form-group">
              <label for="announcementId">Duyuru ID (Düzenleme için)</label>
              <input type="text" id="announcementId" placeholder="Boş bırakın yeni için">
            </div>
            <div class="form-group">
              <label for="announcementTitle">Başlık</label>
              <input type="text" id="announcementTitle" required>
            </div>
            <div class="form-group">
              <label for="announcementContent">İçerik (HTML destekli)</label>
              <textarea id="announcementContent" required></textarea>
            </div>
            <div class="form-group">
              <label for="announcementActive">Aktif</label>
              <input type="checkbox" id="announcementActive" checked>
            </div>
            <button type="submit">Kaydet / Güncelle</button>
            <button type="button" id="deleteAnnouncement">Sil</button>
          </form>
        </div>
        <div id="announcementList">
          <!-- Duyurular burada listelenecek -->
        </div>
        <div id="announcementUpdateResult"></div>
      </div>

      <!-- Modal -->
      <div id="editModal" class="modal">
        <div class="modal-content">
          <h2>Kullanıcı Düzenle</h2>
          <form id="editForm">
            <label for="editPlan">Plan:</label>
            <select id="editPlan">
              <option value="free">Free</option>
              <option value="pro">Pro</option>
            </select>
            <label for="editCredits">Credits:</label>
            <input type="number" id="editCredits" min="0">
            <label for="editExpiration">Expiration Date (YYYY-MM-DD):</label>
            <input type="date" id="editExpiration">
            <button type="button" class="submit-btn" onclick="submitEdit()">Güncelle</button>
            <button type="button" class="close-btn" onclick="closeModal()">İptal</button>
          </form>
        </div>
      </div>

      <script>
        let currentUserId = null;
        const adminUser = "${ADMIN_USER}";
        const adminPass = "${ADMIN_PASS}";
        const basicAuth = btoa(adminUser + ':' + adminPass);

        // Tab switching
        function showTab(tabName) {
          // Hide all tab contents
          document.querySelectorAll('.tab-content').forEach(tab => {
            tab.classList.remove('active');
          });
          // Remove active class from all tabs
          document.querySelectorAll('.tab').forEach(tab => {
            tab.classList.remove('active');
          });
          // Show selected tab content
          document.getElementById(tabName + '-tab').classList.add('active');
          // Add active class to clicked tab
          event.target.classList.add('active');
          
          // Load data for specific tabs
          if (tabName === 'users') {
            loadUsers();
          } else if (tabName === 'stats') {
            loadStats();
          } else if (tabName === 'announcements') {
            loadAnnouncements();
          }
        }

        // Load plugin statistics
        async function loadStats() {
          try {
            const response = await fetch('/admin/plugin-stats', {
              headers: { 'Authorization': 'Basic ' + basicAuth }
            });
            if (!response.ok) throw new Error('Stats yükleme hatası');
            const stats = await response.json();
            
            const statsGrid = document.getElementById('statsGrid');
            statsGrid.innerHTML = `
              <div class="stat-card">
                <div class="stat-number">${stats.total_users}</div>
                <div class="stat-label">Toplam Kullanıcı</div>
              </div>
              <div class="stat-card">
                <div class="stat-number">${stats.free_users}</div>
                <div class="stat-label">Free Kullanıcılar</div>
              </div>
              <div class="stat-card">
                <div class="stat-number">${stats.pro_users}</div>
                <div class="stat-label">Pro Kullanıcılar</div>
              </div>
              <div class="stat-card">
                <div class="stat-number">${stats.active_users}</div>
                <div class="stat-label">Aktif Kullanıcılar</div>
              </div>
              <div class="stat-card">
                <div class="stat-number">${stats.inactive_users}</div>
                <div class="stat-label">Pasif Kullanıcılar</div>
              </div>
              <div class="stat-card">
                <div class="stat-number">v${stats.plugin_version}</div>
                <div class="stat-label">Mevcut Plugin Versiyonu</div>
              </div>
              <div class="stat-card">
                <div class="stat-number">${stats.last_updated}</div>
                <div class="stat-label">Son Güncelleme</div>
              </div>
            `;
          } catch (error) {
            console.error('Stats yükleme hatası:', error);
            document.getElementById('statsGrid').innerHTML = '<p>İstatistikler yüklenirken hata oluştu</p>';
          }
        }

        // Plugin version update
        document.getElementById('pluginVersionForm').addEventListener('submit', async function(e) {
          e.preventDefault();
          
          const formData = {
            version: document.getElementById('pluginVersion').value,
            tested: document.getElementById('pluginTested').value,
            description: document.getElementById('pluginDescription').value,
            changelog: document.getElementById('pluginChangelog').value,
            download_url: document.getElementById('pluginDownloadUrl').value
          };

          try {
            const response = await fetch('/admin/update-plugin-version', {
              method: 'POST',
              headers: { 
                'Content-Type': 'application/json',
                'Authorization': 'Basic ' + basicAuth
              },
              body: JSON.stringify(formData)
            });
            
            const result = await response.json();
            const resultDiv = document.getElementById('pluginUpdateResult');
            
            if (response.ok) {
              resultDiv.innerHTML = `
                <div style="background: #d1e7dd; color: #0f5132; padding: 15px; border-radius: 4px; margin-top: 15px;">
                  <strong>Başarılı!</strong> Plugin versiyonu güncellendi: v${result.updated_version.version}
                </div>
              `;
              document.getElementById('pluginVersionForm').reset();
            } else {
              resultDiv.innerHTML = `
                <div style="background: #f8d7da; color: #842029; padding: 15px; border-radius: 4px; margin-top: 15px;">
                  <strong>Hata:</strong> ${result.error || 'Bilinmeyen hata'}
                </div>
              `;
            }
          } catch (error) {
            document.getElementById('pluginUpdateResult').innerHTML = `
              <div style="background: #f8d7da; color: #842029; padding: 15px; border-radius: 4px; margin-top: 15px;">
                <strong>Hata:</strong> ${error.message}
              </div>
            `;
          }
        });

        // Duyurular yükleme
        async function loadAnnouncements() {
          try {
            const response = await fetch('/admin/announcements', {
              headers: { 'Authorization': 'Basic ' + basicAuth }
            });
            if (!response.ok) throw new Error('Duyurular yükleme hatası');
            const announcements = await response.json();
            
            const list = document.getElementById('announcementList');
            list.innerHTML = '<h3>Mevcut Duyurular</h3><ul>';
            announcements.forEach(ann => {
              list.innerHTML += `<li data-id="${ann._id}">
                <strong>${ann.title}</strong> (${ann.active ? 'Aktif' : 'Pasif'}) - ${new Date(ann.date).toLocaleDateString()}
                <button onclick="editAnnouncement('${ann._id}')">Düzenle</button>
              </li>`;
            });
            list.innerHTML += '</ul>';
          } catch (error) {
            console.error('Duyurular yükleme hatası:', error);
          }
        }

        async function editAnnouncement(id) {
          try {
            const response = await fetch(`/admin/announcements/${id}`, {
              headers: { 'Authorization': 'Basic ' + basicAuth }
            });
            const ann = await response.json();
            document.getElementById('announcementId').value = ann._id;
            document.getElementById('announcementTitle').value = ann.title;
            document.getElementById('announcementContent').value = ann.content;
            document.getElementById('announcementActive').checked = ann.active;
          } catch (error) {
            console.error('Düzenleme hatası:', error);
          }
        }

        document.getElementById('announcementForm').addEventListener('submit', async function(e) {
          e.preventDefault();
          const id = document.getElementById('announcementId').value;
          const formData = {
            title: document.getElementById('announcementTitle').value,
            content: document.getElementById('announcementContent').value,
            active: document.getElementById('announcementActive').checked
          };

          try {
            const url = id ? `/admin/announcements/${id}` : '/admin/announcements';
            const method = id ? 'PUT' : 'POST';
            const response = await fetch(url, {
              method,
              headers: { 
                'Content-Type': 'application/json',
                'Authorization': 'Basic ' + basicAuth
              },
              body: JSON.stringify(formData)
            });
            
            const result = await response.json();
            const resultDiv = document.getElementById('announcementUpdateResult');
            if (response.ok) {
              resultDiv.innerHTML = '<div style="background: #d1e7dd; color: #0f5132; padding: 15px;">Başarılı! Duyuru güncellendi.</div>';
              loadAnnouncements();
              document.getElementById('announcementForm').reset();
            } else {
              resultDiv.innerHTML = '<div style="background: #f8d7da; color: #842029; padding: 15px;">Hata: ' + result.error + '</div>';
            }
          } catch (error) {
            console.error(error);
          }
        });

        document.getElementById('deleteAnnouncement').addEventListener('click', async function() {
          const id = document.getElementById('announcementId').value;
          if (!id || !confirm('Silmek istediğinize emin misiniz?')) return;
          
          try {
            const response = await fetch(`/admin/announcements/${id}`, {
              method: 'DELETE',
              headers: { 'Authorization': 'Basic ' + basicAuth }
            });
            if (response.ok) {
              alert('Silindi!');
              loadAnnouncements();
              document.getElementById('announcementForm').reset();
            } else {
              alert('Hata: ' + (await response.json()).error);
            }
          } catch (error) {
            console.error(error);
          }
        });

        // Kullanıcıları yükleme fonksiyonu
        async function loadUsers() {
          try {
            const search = document.getElementById('searchInput').value;
            const plan = document.getElementById('planFilter').value;
            const url = '/admin/users?search=' + encodeURIComponent(search) + '&plan=' + plan;
            
            const response = await fetch(url, {
              headers: { 'Authorization': 'Basic ' + basicAuth }
            });
            
            if (!response.ok) throw new Error('Yükleme hatası');
            const users = await response.json();
            
            const tbody = document.querySelector('#usersTable tbody');
            tbody.innerHTML = '';
            
            users.forEach(user => {
              const tr = document.createElement('tr');
              tr.innerHTML = 
                '<td>' + user.email + '</td>' +
                '<td>' + (user.phone || 'N/A') + '</td>' +
                '<td>' + (user.site || 'N/A') + '</td>' +
                '<td>' + user.plan + '</td>' +
                '<td>' + user.credits + '</td>' +
                '<td>' + (user.expirationDate ? new Date(user.expirationDate).toLocaleDateString('tr-TR') : 'N/A') + '</td>' +
                '<td>' + new Date(user.registrationDate).toLocaleDateString('tr-TR') + '</td>' +
                '<td>' + (user.active ? 'Aktif' : 'Pasif') + '</td>' +
                '<td>' +
                  '<button onclick="openModal(\'' + user._id + '\', \'' + user.plan + '\', ' + user.credits + ', \'' + (user.expirationDate ? new Date(user.expirationDate).toISOString().split('T')[0] : '') + '\')">Düzenle</button>' +
                '</td>';
              tbody.appendChild(tr);
            });
            
            // İstatistikleri güncelle
            updateStats();
          } catch (error) {
            console.error('Hata:', error);
            alert('Kullanıcılar yüklenirken bir hata oluştu.');
          }
        }

        // İstatistikleri güncelleme fonksiyonu
        async function updateStats() {
          try {
            const response = await fetch('/admin/users', {
              headers: { 'Authorization': 'Basic ' + basicAuth }
            });
            if (!response.ok) throw new Error('İstatistik hatası');
            const allUsers = await response.json();
            const freeCount = allUsers.filter(u => u.plan === 'free').length;
            const proCount = allUsers.filter(u => u.plan === 'pro').length;
            const inactiveCount = allUsers.filter(u => !u.active).length;
            
            document.getElementById('stats').innerHTML = '<p><strong>Free: ' + freeCount + 
              '</strong> | <strong>Pro: ' + proCount + 
              '</strong> | <strong>Pasif: ' + inactiveCount + '</strong></p>';
          } catch (error) {
            console.error('Hata:', error);
          }
        }

        // Modal açma
        function openModal(userId, plan, credits, expiration) {
          currentUserId = userId;
          document.getElementById('editPlan').value = plan;
          document.getElementById('editCredits').value = credits;
          document.getElementById('editExpiration').value = expiration;
          document.getElementById('editModal').style.display = 'flex';
        }

        // Modal kapama
        function closeModal() {
          document.getElementById('editModal').style.display = 'none';
        }

        // Düzenleme gönderme
        async function submitEdit() {
          const plan = document.getElementById('editPlan').value;
          const credits = parseInt(document.getElementById('editCredits').value);
          const expiration = document.getElementById('editExpiration').value;
          
          if (plan && !isNaN(credits)) {
            try {
              const response = await fetch('/admin/update-user', {
                method: 'POST',
                headers: { 
                  'Content-Type': 'application/json',
                  'Authorization': 'Basic ' + basicAuth
                },
                body: JSON.stringify({ 
                  userId: currentUserId, 
                  plan, 
                  credits, 
                  expirationDate: expiration 
                })
              });
              
              if (response.ok) {
                alert('Güncellendi!');
                closeModal();
                loadUsers();
              } else {
                throw new Error('Güncelleme hatası');
              }
            } catch (error) {
              console.error('Hata:', error);
              alert('Güncelleme sırasında bir hata oluştu!');
            }
          } else {
            alert('Zorunlu alanları doldurun.');
          }
        }

        // İlk yükleme
        loadUsers();
        loadStats();

        // Modal dışına tıklayınca kapatma
        window.onclick = function(event) {
          const modal = document.getElementById('editModal');
          if (event.target === modal) {
            closeModal();
          }
        }
      </script>
    </body>
    </html>
  `);
});

// Vercel için export
module.exports = app;
