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
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

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

async function resetCreditsIfNeeded(user) {
  const now = new Date();
  if (now.getMonth() !== user.lastReset.getMonth() || now.getFullYear() !== user.lastReset.getFullYear()) {
    user.credits = user.plan === 'pro' ? 120 : 20;
    user.lastReset = now;
    await user.save();
  }
}

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
        changelog: `<h4>Versiyon 3.0</h4><ul><li>Güncelleme sırasında oluşan hata çözüldü.</li></ul>`
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

app.get('/wp-update-check', async (req, res) => {
  const { action, plugin } = req.query;
  if (action === 'get_version' && plugin === 'sss-ai') {
    const pluginVersion = await getPluginVersion();
    res.json({
      version: pluginVersion.version,
      tested: pluginVersion.tested,
      last_updated: pluginVersion.last_updated instanceof Date ? pluginVersion.last_updated.toISOString().split('T')[0] : pluginVersion.last_updated,
      download_url: pluginVersion.download_url,
      description: pluginVersion.description,
      changelog: pluginVersion.changelog
    });
  } else {
    res.status(404).json({ error: 'Invalid request' });
  }
});

app.get('/download/sss-ai-v3.1.zip', (req, res) => {
  res.redirect('https://github.com/servisi/faq-ai/releases/latest/download/sss-ai.zip');
});

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

app.post('/register', async (req, res) => {
  const { email, phone, site } = req.body;
  if (!email || !phone) return res.status(400).json({ error: 'Email ve telefon gereklidir' });
  let user = await User.findOne({ email });
  if (user) {
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ token });
  }
  user = new User({ email, phone, site, registrationDate: new Date() });
  await user.save();
  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token });
});

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

app.post('/api/generate-faq', authenticate, async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  await checkProExpiration(user);
  await resetCreditsIfNeeded(user);
  if (user.credits <= 0) return res.status(402).json({ error: 'no_credits' });

  const { title, num_questions, language = 'tr' } = req.body;
  let recentNews = '';
  const searchQuerySuffix = language === 'tr' ? 'son haberler' : 'latest news';
  const serperHl = language;
  const serperGl = language === 'tr' ? 'tr' : 'us';

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
    recentNews = results.map(r => `${r.title}: ${r.snippet} (Kaynak: ${r.link})`).join('\n');
  } catch (searchErr) {
    console.error('Search error:', searchErr);
    recentNews = language === 'tr' ? 'Güncel haberler tespit edilemedi.' : 'Recent news could not be detected.';
  }

  const prompt = language === 'tr'
    ? `Başlık: ${title}. Son güncel bilgiler: ${recentNews}. Bu güncel bilgilerle en çok aranan ${num_questions} FAQ sorusu üret ve her birine kısa, bilgilendirici cevap ver. Kişisel bilgiler, rezervasyon, iptal randevu gibi canlı bilgiler, Politik, dini, finansal, tıbbi gibi hassas bilgilerden kaçın. Yanıltıcı, kesinliği olmayan bilgiler verme. Cevabı Google snipet üzerinde çıkabilecek şekilde yapılandır. Yanıtı JSON formatında ver: {"faqs": [{"question": "Soru", "answer": "Cevap"}]}`
    : `Title: ${title}. Recent information: ${recentNews}. Based on this current information, generate the top ${num_questions} FAQ questions and provide short, informative answers for each. Avoid personal information, live information like reservations, canceled appointments, and sensitive information like political, religious, financial, and medical. Avoid providing misleading or inaccurate information. Structure your answer so it appears in the Google snippet. Respond in JSON format: {"faqs": [{"question": "Question", "answer": "Answer"}]}`;

  try {
    const completion = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      response_format: { type: "json_object" }
    });
    const content = completion.choices[0].message.content;
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

app.get('/admin/users', adminAuth, async (req, res) => {
  const { search, plan } = req.query;
  let query = {};
  if (plan && plan !== 'all') query.plan = plan;
  if (search) query.email = { $regex: search, $options: 'i' };
  const users = await User.find(query, 'email phone site plan credits expirationDate registrationDate active');
  res.json(users);
});

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
      last_updated: pluginVersion.last_updated instanceof Date ? pluginVersion.last_updated.toISOString().split('T')[0] : pluginVersion.last_updated
    });
  } catch (error) {
    res.status(500).json({ error: 'Statistics fetch failed', details: error.message });
  }
});

app.post('/admin/update-plugin-version', adminAuth, async (req, res) => {
  const { version, tested, description, changelog, download_url } = req.body;
  if (!version) return res.status(400).json({ error: 'Version is required' });
  try {
    let pluginVersion = await PluginVersion.findOne({ plugin_name: 'sss-ai' }) || new PluginVersion({ plugin_name: 'sss-ai' });
    if (version) pluginVersion.version = version;
    if (tested) pluginVersion.tested = tested;
    if (description) pluginVersion.description = description;
    if (changelog) pluginVersion.changelog = changelog;
    if (download_url) pluginVersion.download_url = download_url;
    pluginVersion.last_updated = new Date();
    await pluginVersion.save();
    res.json({ success: true, message: 'Plugin version updated successfully', updated_version: pluginVersion });
  } catch (error) {
    res.status(500).json({ error: 'Database update failed', details: error.message });
  }
});

app.get('/announcements', async (req, res) => {
  const announcements = await Announcement.find({ active: true }).sort({ date: -1 });
  res.json(announcements);
});

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
  const { title, content, active = true } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'Title and content required' });
  const ann = new Announcement({ title, content, active });
  await ann.save();
  res.json({ success: true });
});

app.put('/admin/announcements/:id', adminAuth, async (req, res) => {
  const { title, content, active } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'Title and content required' });
  await Announcement.findByIdAndUpdate(req.params.id, { title, content, active });
  res.json({ success: true });
});

app.delete('/admin/announcements/:id', adminAuth, async (req, res) => {
  await Announcement.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});

app.get('/admin', adminAuth, (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <title>Admin Panel – AI FAQ</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f4f6f9;margin:0;padding:30px;color:#333}
    h1{color:#007bff;text-align:center;margin-bottom:30px}
    .tabs{display:flex;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.1);margin-bottom:30px}
    .tab{flex:1;padding:15px 20px;background:#f8f9fa;border:none;cursor:pointer;font-size:16px;transition:.3s}
    .tab:hover{background:#e9ecef}
    .tab.active{background:#007bff;color:#fff}
    .tab-content{display:none}
    .tab-content.active{display:block}
    .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:30px}
    .stat-card{background:#fff;padding:20px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);text-align:center}
    .stat-number{font-size:2em;font-weight:bold;color:#007bff}
    .stat-label{color:#666;margin-top:5px}
    #controls{display:flex;flex-wrap:wrap;gap:15px;margin-bottom:30px;justify-content:center}
    input,select,textarea{padding:12px;border:1px solid #ced4da;border-radius:6px;font-size:1em;width:100%}
    button{padding:12px 20px;background:#007bff;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:1em}
    button:hover{background:#0056b3}
    table{width:100%;border-collapse:separate;border-spacing:0;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 4px 12px rgba(0,0,0,.1)}
    th,td{padding:15px;text-align:left;border-bottom:1px solid #dee2e6}
    th{background:#007bff;color:#fff}
    tr:hover{background:#f1f3f5}
    .modal{display:none;position:fixed;z-index:1000;left:0;top:0;width:100%;height:100%;background:rgba(0,0,0,.5);justify-content:center;align-items:center}
    .modal-content{background:#fff;padding:30px;border-radius:8px;width:90%;max-width:500px;box-shadow:0 4px 20px rgba(0,0,0,.2)}
    .close-btn{background:#dc3545}.submit-btn{background:#28a745}
    @media(max-width:768px){#controls{flex-direction:column}.modal-content{width:95%}}
  </style>
</head>
<body>
  <h1>AI FAQ Admin Panel</h1>

  <div class="tabs">
    <button class="tab active" onclick="showTab(event,'users')">Kullanıcı Yönetimi</button>
    <button class="tab" onclick="showTab(event,'plugin')">Plugin Yönetimi</button>
    <button class="tab" onclick="showTab(event,'stats')">İstatistikler</button>
    <button class="tab" onclick="showTab(event,'announcements')">Duyurular</button>
  </div>

  <div id="users-tab" class="tab-content active">
    <h2>Kullanıcı Yönetimi</h2>
    <div id="controls">
      <input type="text" id="searchInput" placeholder="Email ile ara">
      <select id="planFilter">
        <option value="all">Tümü</option>
        <option value="free">Free</option>
        <option value="pro">Pro</option>
      </select>
      <button onclick="loadUsers()">Ara/Filtrele</button>
    </div>
    <div id="stats"></div>
    <table id="usersTable">
      <thead><tr>
        <th>Email</th><th>Telefon</th><th>Site</th><th>Plan</th><th>Credits</th>
        <th>Son Geçerlilik</th><th>Kayıt Tarihi</th><th>Durum</th><th>İşlem</th>
      </tr></thead>
      <tbody></tbody>
    </table>
  </div>

  <div id="plugin-tab" class="tab-content">
    <h2>Plugin Sürüm Yönetimi</h2>
    <form id="pluginVersionForm">
      <input type="text" id="pluginVersion" placeholder="Versiyon (örn: 3.1)" required>
      <input type="text" id="pluginTested" placeholder="WordPress versiyonu (örn: 6.8)" required>
      <textarea id="pluginDescription" placeholder="Açıklama"></textarea>
      <textarea id="pluginChangelog" placeholder="Changelog (HTML)"></textarea>
      <input type="url" id="pluginDownloadUrl" placeholder="İndirme URL">
      <button>Güncelle</button>
    </form>
    <div id="pluginUpdateResult"></div>
  </div>

  <div id="stats-tab" class="tab-content">
    <h2>Genel İstatistikler</h2>
    <div class="stats-grid" id="statsGrid"></div>
  </div>

  <div id="announcements-tab" class="tab-content">
    <h2>Duyurular Yönetimi</h2>
    <form id="announcementForm">
      <input type="text" id="announcementId" placeholder="Duyuru ID (düzenleme için, boş bırak yeni)">
      <input type="text" id="announcementTitle" placeholder="Başlık" required>
      <textarea id="announcementContent" placeholder="İçerik (HTML)" required></textarea>
      <label><input type="checkbox" id="announcementActive" checked> Aktif</label>
      <button>Kaydet / Güncelle</button>
      <button type="button" id="deleteAnnouncement">Sil</button>
    </form>
    <div id="announcementList"></div>
    <div id="announcementUpdateResult"></div>
  </div>

  <div id="editModal" class="modal">
    <div class="modal-content">
      <h2>Kullanıcı Düzenle</h2>
      <label>Plan</label>
      <select id="editPlan"><option value="free">Free</option><option value="pro">Pro</option></select>
      <label>Credits</label>
      <input type="number" id="editCredits" min="0">
      <label>Son Geçerlilik</label>
      <input type="date" id="editExpiration">
      <button class="submit-btn" onclick="submitEdit()">Güncelle</button>
      <button class="close-btn" onclick="closeModal()">İptal</button>
    </div>
  </div>

  <script>
    let currentUserId = null;
    const adminUser = "${ADMIN_USER}";
    const adminPass = "${ADMIN_PASS}";
    const basicAuth = 'Basic ' + btoa(adminUser + ':' + adminPass);

    function showTab(event, tabName) {
      document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.getElementById(tabName + '-tab').classList.add('active');
      event.target.classList.add('active');
      if (tabName === 'users') loadUsers();
      else if (tabName === 'stats') loadStats();
      else if (tabName === 'announcements') loadAnnouncements();
    }

    async function loadUsers() {
      const search = document.getElementById('searchInput').value;
      const plan = document.getElementById('planFilter').value;
      const url = '/admin/users?search=' + encodeURIComponent(search) + '&plan=' + plan;
      const res = await fetch(url, { headers: { Authorization: basicAuth } });
      const users = await res.json();
      const tbody = document.querySelector('#usersTable tbody');
      tbody.innerHTML = '';
      users.forEach(u => {
        const tr = document.createElement('tr');
        tr.innerHTML = \`
          <td>\${u.email}</td>
          <td>\${u.phone || 'N/A'}</td>
          <td>\${u.site || 'N/A'}</td>
          <td>\${u.plan}</td>
          <td>\${u.credits}</td>
          <td>\${u.expirationDate ? new Date(u.expirationDate).toLocaleDateString('tr-TR') : 'N/A'}</td>
          <td>\${new Date(u.registrationDate).toLocaleDateString('tr-TR')}</td>
          <td>\${u.active ? 'Aktif' : 'Pasif'}</td>
          <td><button onclick="openModal('\${u._id}','\${u.plan}',\${u.credits},'\${u.expirationDate ? new Date(u.expirationDate).toISOString().split('T')[0] : ''}')">Düzenle</button></td>
        \`;
        tbody.appendChild(tr);
      });
      updateStats();
    }

    async function updateStats() {
      const res = await fetch('/admin/users', { headers: { Authorization: basicAuth } });
      const all = await res.json();
      const free = all.filter(u => u.plan === 'free').length;
      const pro = all.filter(u => u.plan === 'pro').length;
      const inactive = all.filter(u => !u.active).length;
      document.getElementById('stats').innerHTML = \`<p><strong>Free: \${free}</strong> | <strong>Pro: \${pro}</strong> | <strong>Pasif: \${inactive}</strong></p>\`;
    }

    async function loadStats() {
      const res = await fetch('/admin/plugin-stats', { headers: { Authorization: basicAuth } });
      const stats = await res.json();
      document.getElementById('statsGrid').innerHTML = \`
        <div class="stat-card"><div class="stat-number">\${stats.total_users}</div><div class="stat-label">Toplam Kullanıcı</div></div>
        <div class="stat-card"><div class="stat-number">\${stats.free_users}</div><div class="stat-label">Free Kullanıcılar</div></div>
        <div class="stat-card"><div class="stat-number">\${stats.pro_users}</div><div class="stat-label">Pro Kullanıcılar</div></div>
        <div class="stat-card"><div class="stat-number">\${stats.active_users}</div><div class="stat-label">Aktif Kullanıcılar</div></div>
        <div class="stat-card"><div class="stat-number">\${stats.inactive_users}</div><div class="stat-label">Pasif Kullanıcılar</div></div>
        <div class="stat-card"><div class="stat-number">v\${stats.plugin_version}</div><div class="stat-label">Plugin Versiyonu</div></div>
        <div class="stat-card"><div class="stat-number">\${stats.last_updated}</div><div class="stat-label">Son Güncelleme</div></div>
      \`;
    }

    async function loadAnnouncements() {
      const res = await fetch('/admin/announcements', { headers: { Authorization: basicAuth } });
      const anns = await res.json();
      const list = document.getElementById('announcementList');
      list.innerHTML = '<h3>Mevcut Duyurular</h3><ul>' + anns.map(a => \`
        <li>
          <strong>\${a.title}</strong> (\${a.active ? 'Aktif' : 'Pasif'}) - \${new Date(a.date).toLocaleDateString()}
          <button onclick="editAnnouncement('\${a._id}')">Düzenle</button>
        </li>\`).join('') + '</ul>';
    }

    function openModal(uid, plan, credits, exp) {
      currentUserId = uid;
      document.getElementById('editPlan').value = plan;
      document.getElementById('editCredits').value = credits;
      document.getElementById('editExpiration').value = exp;
      document.getElementById('editModal').style.display = 'flex';
    }
    function closeModal() { document.getElementById('editModal').style.display = 'none'; }

    async function submitEdit() {
      const plan = document.getElementById('editPlan').value;
      const credits = parseInt(document.getElementById('editCredits').value);
      const expiration = document.getElementById('editExpiration').value;
      if (!plan || isNaN(credits)) return alert('Zorunlu alanları doldurun.');
      const res = await fetch('/admin/update-user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: basicAuth },
        body: JSON.stringify({ userId: currentUserId, plan, credits, expirationDate: expiration })
      });
      if (res.ok) { alert('Güncellendi!'); closeModal(); loadUsers(); }
      else alert('Hata!');
    }

    document.getElementById('pluginVersionForm').addEventListener('submit', async e => {
      e.preventDefault();
      const body = {
        version: document.getElementById('pluginVersion').value,
        tested: document.getElementById('pluginTested').value,
        description: document.getElementById('pluginDescription').value,
        changelog: document.getElementById('pluginChangelog').value,
        download_url: document.getElementById('pluginDownloadUrl').value
      };
      const res = await fetch('/admin/update-plugin-version', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: basicAuth },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      document.getElementById('pluginUpdateResult').innerHTML = \`<div style="padding:15px;border-radius:4px;color:#fff;background:\${res.ok?'#28a745':'#dc3545'}">\${data.message || data.error}</div>\`;
    });

    document.getElementById('announcementForm').addEventListener('submit', async e => {
      e.preventDefault();
      const id = document.getElementById('announcementId').value;
      const body = {
        title: document.getElementById('announcementTitle').value,
        content: document.getElementById('announcementContent').value,
        active: document.getElementById('announcementActive').checked
      };
      const res = await fetch(id ? \`/admin/announcements/\${id}\` : '/admin/announcements', {
        method: id ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: basicAuth },
        body: JSON.stringify(body)
      });
      if (res.ok) { alert('Kaydedildi'); loadAnnouncements(); document.getElementById('announcementForm').reset(); }
      else alert('Hata!');
    });

    document.getElementById('deleteAnnouncement').addEventListener('click', async () => {
      const id = document.getElementById('announcementId').value;
      if (!id || !confirm('Silmek istediğinize emin misiniz?')) return;
      const res = await fetch(\`/admin/announcements/\${id}\`, { method: 'DELETE', headers: { Authorization: basicAuth } });
      if (res.ok) { alert('Silindi'); loadAnnouncements(); document.getElementById('announcementForm').reset(); }
      else alert('Hata!');
    });

    async function editAnnouncement(id) {
      const res = await fetch(\`/admin/announcements/\${id}\`, { headers: { Authorization: basicAuth } });
      const a = await res.json();
      document.getElementById('announcementId').value = a._id;
      document.getElementById('announcementTitle').value = a.title;
      document.getElementById('announcementContent').value = a.content;
      document.getElementById('announcementActive').checked = a.active;
    }

    loadUsers();
    loadStats();
    window.onclick = e => { if (e.target === document.getElementById('editModal')) closeModal(); };
  </script>
</body>
</html>`);
});

module.exports = app;
