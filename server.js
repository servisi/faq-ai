// server.js – Ücretsiz sürüm backend
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const cors = require('cors');
const basicAuth = require('basic-auth');
const OpenAI = require('openai');
const axios = require('axios');
const app = express();

app.use(express.json());
app.use(cors({ origin: '*', methods: ['GET', 'POST'] }));

mongoose.connect(process.env.MONGO_URI);
const JWT_SECRET = process.env.JWT_SECRET;
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const SERPER_API_KEY = process.env.SERPER_API_KEY;

/* ----------  Free User Schema  ---------- */
const FreeUserSchema = new mongoose.Schema({
  email:        { type: String, unique: true },
  phone:        String,
  site:         String,
  credits:      { type: Number, default: 20 },
  plan:         { type: String, default: 'free' },
  lastReset:    { type: Date, default: Date.now },
  registeredAt: { type: Date, default: Date.now },
  status:       { type: String, default: 'active' } // active | disabled
});
const FreeUser = mongoose.model('FreeUser', FreeUserSchema);

/* ----------  Admin auth  ---------- */
function adminAuth(req, res, next) {
  const user = basicAuth(req);
  if (!user || user.name !== process.env.ADMIN_USER || user.pass !== process.env.ADMIN_PASS) {
    res.set('WWW-Authenticate', 'Basic realm="Admin"');
    return res.status(401).send('Unauthorized');
  }
  next();
}

/* ----------  WordPress update check  ---------- */
const PLUGIN_VERSION = {
  version: '3.0-free',
  tested: '6.4',
  last_updated: '2025-07-30',
  download_url: 'https://publicus.com.tr/sss-ai-free.zip',
  description: 'Ücretsiz: sayfa başlığına göre tek seferlik SSS oluşturur.',
  changelog: '<h4>Versiyon 3.0-free</h4><ul><li>Ücretsiz sürüm ilk sürüm</li></ul>'
};
app.get('/wp-update-check', (req, res) => {
  const { action, plugin } = req.query;
  if (action === 'get_version' && plugin === 'sss-ai') return res.json(PLUGIN_VERSION);
  res.status(404).json({ error: 'Invalid' });
});

/* ----------  Free Registration  ---------- */
app.post('/register-free', async (req, res) => {
  const { email, phone, site } = req.body;
  if (!email) return res.status(400).json({ error: 'Email gerekli' });
  let user = await FreeUser.findOne({ email });
  if (user) {
    if (user.status === 'disabled') return res.status(403).json({ error: 'Hesap devre dışı' });
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ token });
  }
  user = new FreeUser({ email, phone, site });
  await user.save();
  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token });
});

/* ----------  Free FAQ Generation  ---------- */
app.post('/api/generate-faq-free', async (req, res) => {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token yok' });
  let decoded;
  try { decoded = jwt.verify(token, JWT_SECRET); } catch { return res.status(401).json({ error: 'Geçersiz token' }); }
  const user = await FreeUser.findById(decoded.userId);
  if (!user || user.status === 'disabled') return res.status(403).json({ error: 'Hesap devre dışı' });
  if (user.credits <= 0) return res.status(402).json({ error: 'no_credits' });

  const { title, num_questions = 5, language = 'tr' } = req.body;

  /* Monthly reset */
  const now = new Date();
  if (now.getMonth() !== user.lastReset.getMonth() || now.getFullYear() !== user.lastReset.getFullYear()) {
    user.credits = 20;
    user.lastReset = now;
    await user.save();
  }

  /* Search & build prompt */
  let news = '';
  try {
    const q = language === 'tr' ? `${title} son haberler` : `${title} latest news`;
    const { data } = await axios.post('https://google.serper.dev/search',
      { q, num: 3, tbs: 'qdr:w', hl: language, gl: language === 'tr' ? 'tr' : 'us' },
      { headers: { 'X-API-KEY': SERPER_API_KEY } }
    );
    news = (data.organic || []).map(r => `${r.title}: ${r.snippet}`).join('\n');
  } catch { news = ''; }

  const prompt = language === 'tr'
    ? `Başlık: ${title}\nGüncel bilgiler: ${news}\nBu bilgilerle en çok merak edilen ${num_questions} FAQ sorusu ve kısa cevapları JSON: {"faqs":[{"question":"...","answer":"..."}]}`
    : `Title: ${title}\nLatest info: ${news}\nGenerate ${num_questions} FAQ questions and concise answers in JSON: {"faqs":[{"question":"...","answer":"..."}]}`;

  try {
    const completion = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      response_format: { type: 'json_object' }
    });
    const body = JSON.parse(completion.choices[0].message.content);
    if (!body.faqs) throw new Error('Yanlış format');
    user.credits -= 1;
    await user.save();
    res.json({ faqs: body.faqs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ----------  Admin routes (unchanged)  ---------- */
app.get('/admin/users', adminAuth, async (req, res) => {
  const { search = '', plan = 'all' } = req.query;
  const q = {};
  if (plan !== 'all') q.plan = plan;
  if (search) q.email = { $regex: search, $options: 'i' };
  const users = await FreeUser.find(q, 'email phone site plan credits status registeredAt');
  res.json(users);
});
app.post('/admin/update-user', adminAuth, async (req, res) => {
  const { userId, plan, credits, status } = req.body;
  const user = await FreeUser.findById(userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (plan !== undefined) user.plan = plan;
  if (credits !== undefined) user.credits = credits;
  if (status !== undefined) user.status = status;
  await user.save();
  res.json({ success: true });
});
app.get('/admin/plugin-stats', adminAuth, async (req, res) => {
  const [total, active, disabled] = await Promise.all([
    FreeUser.countDocuments(),
    FreeUser.countDocuments({ status: 'active' }),
    FreeUser.countDocuments({ status: 'disabled' })
  ]);
  res.json({ total_users: total, active_users: active, disabled_users: disabled, plugin_version: PLUGIN_VERSION.version });
});
app.post('/admin/update-plugin-version', adminAuth, (req, res) => {
  const { version, tested, description, changelog, download_url } = req.body;
  if (version) PLUGIN_VERSION.version = version;
  if (tested) PLUGIN_VERSION.tested = tested;
  if (description) PLUGIN_VERSION.description = description;
  if (changelog) PLUGIN_VERSION.changelog = changelog;
  if (download_url) PLUGIN_VERSION.download_url = download_url;
  PLUGIN_VERSION.last_updated = new Date().toISOString().split('T')[0];
  res.json({ success: true, updated_version: PLUGIN_VERSION });
});

/* ----------  Admin HTML page (unchanged)  ---------- */
app.get('/admin', adminAuth, (req, res) => {
  res.send(`
<!doctype html><html lang="tr"><head><meta charset="utf-8"><title>Admin – AI FAQ Free</title>
<style>body{font-family:system-ui;background:#f4f6f9;margin:40px;color:#333}
h1{color:#007bff}.stat-card{background:#fff;padding:20px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);margin:10px;flex:1 1 200px;text-align:center}
.stats-grid{display:flex;flex-wrap:wrap;gap:20px;margin-bottom:30px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.1)}
th,td{padding:15px;text-align:left;border-bottom:1px solid #eee}
th{background:#007bff;color:#fff}
button{padding:10px 15px;background:#007bff;color:#fff;border:none;border-radius:4px;cursor:pointer}
button:hover{background:#0056b3}</style>
</head><body><h1>AI FAQ Free Admin</h1>
<div class="stats-grid" id="statsGrid">Yükleniyor...</div>
<table><thead><tr><th>E-posta</th><th>Telefon</th><th>Site</th><th>Credits</th><th>Durum</th></tr></thead><tbody id="tblBody"></tbody></table>
<script>
fetch('/admin/plugin-stats').then(r=>r.json()).then(d=>{
  document.getElementById('statsGrid').innerHTML=
  '<div class="stat-card"><strong>'+d.total_users+'</strong><br>Toplam Kullanıcı</div>'+
  '<div class="stat-card"><strong>'+d.active_users+'</strong><br>Aktif Kullanıcı</div>'+
  '<div class="stat-card"><strong>'+d.disabled_users+'</strong><br>Devre Dışı</div>';
});
fetch('/admin/users').then(r=>r.json()).then(users=>{
  const b=document.getElementById('tblBody');
  b.innerHTML='';
  users.forEach(u=>{
    b.insertAdjacentHTML('beforeend','<tr><td>'+u.email+'</td><td>'+u.phone+'</td><td><a href="'+u.site+'" target="_blank">'+u.site+'</a></td><td>'+u.credits+'</td><td>'+u.status+'</td></tr>');
  });
});
</script></body></html>`);
});

module.exports = app;
