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
  credits: { type: Number, default: 20 },
  lastReset: { type: Date, default: Date.now },
  plan: { type: String, default: 'free' },
  expirationDate: { type: Date, default: null }
});
const User = mongoose.model('User', UserSchema);

const openai = new OpenAI({ 
  apiKey: process.env.DEEPSEEK_API_KEY,
  baseURL: 'https://api.deepseek.com'
});
const JWT_SECRET = process.env.JWT_SECRET;
const SERPAPI_KEY = process.env.SERPAPI_KEY;
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

// Kayıt Endpoint
app.post('/register', async (req, res) => {
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
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  await checkProExpiration(user);
  await resetCreditsIfNeeded(user);

  if (user.credits <= 0) {
    return res.status(402).json({ error: 'no_credits' });
  }

  const { title, num_questions } = req.body;

  let recentNews = '';
  try {
    const searchResponse = await axios.get('https://serpapi.com/search', {
      params: {
        q: `${title} son haberler`,
        api_key: SERPAPI_KEY,
        num: 5,
        tbs: 'qdr:w'
      }
    });
    const results = searchResponse.data.organic_results || [];
    recentNews = results.map(result => `${result.title}: ${result.snippet} (Kaynak: ${result.link})`).join('\n');
  } catch (searchErr) {
    console.error('Search error:', searchErr);
    recentNews = 'Güncel haberler tespit edilemedi.';
  }

  const prompt = `Başlık: ${title}. Son güncel haberler ve bilgiler: ${recentNews}. Bu güncel bilgilerle en çok aranan ${num_questions} FAQ sorusu üret ve her birine kısa, bilgilendirici cevap ver. Yanıtı JSON formatında ver: {"faqs": [{"question": "Soru", "answer": "Cevap"}]}`;

  try {
    const completion = await openai.chat.completions.create({
      model: 'deepseek-chat', // DeepSeek chat modeli
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
    console.error('DeepSeek error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Admin Users Endpoint (with search and plan filter)
app.get('/admin/users', adminAuth, async (req, res) => {
  const { search, plan } = req.query;
  let query = {};
  if (plan && plan !== 'all') query.plan = plan;
  if (search) query.email = { $regex: search, $options: 'i' }; // Email search, case-insensitive
  const users = await User.find(query, 'email plan credits expirationDate lastReset');
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

// Admin Panel HTML Page
app.get('/admin', adminAuth, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Panel - AI FAQ Users</title>
      <style>
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
        button { margin-left: 10px; }
        #controls { margin-bottom: 20px; }
      </style>
    </head>
    <body>
      <h1>Kullanıcı Yönetimi</h1>
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
            <th>Plan</th>
            <th>Credits</th>
            <th>Expiration Date</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>

      <script>
        async function loadUsers() {
          const search = document.getElementById('searchInput').value;
          const plan = document.getElementById('planFilter').value;
          const url = \`/admin/users?search=\${encodeURIComponent(search)}&plan=\${plan}\`;
          const response = await fetch(url);
          const users = await response.json();
          const tbody = document.querySelector('#usersTable tbody');
          tbody.innerHTML = '';
          users.forEach(user => {
            const tr = document.createElement('tr');
            tr.innerHTML = \`
              <td>\${user.email}</td>
              <td>\${user.plan}</td>
              <td>\${user.credits}</td>
              <td>\${user.expirationDate ? new Date(user.expirationDate).toLocaleDateString() : 'N/A'}</td>
              <td>
                <button onclick="editUser('\${user._id}')">Düzenle</button>
              </td>
            \`;
            tbody.appendChild(tr);
          });

          // Stats hesapla (tüm users fetch etmeden, filtered'dan değil - tüm için ayrı fetch)
          const allResponse = await fetch('/admin/users');
          const allUsers = await allResponse.json();
          const freeCount = allUsers.filter(u => u.plan === 'free').length;
          const proCount = allUsers.filter(u => u.plan === 'pro').length;
          document.getElementById('stats').innerHTML = \`<p><strong>Toplam Free Kullanıcı: \${freeCount}</strong> | <strong>Toplam Pro Kullanıcı: \${proCount}</strong></p>\`;
        }

        async function editUser(userId) {
          const plan = prompt('Yeni Plan (free/pro):');
          const credits = prompt('Yeni Credits:');
          const expiration = prompt('Yeni Expiration Date (YYYY-MM-DD):');
          
          const response = await fetch('/admin/update-user', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ userId, plan, credits: parseInt(credits), expirationDate: expiration })
          });
          if (response.ok) {
            alert('Güncellendi!');
            loadUsers();
          } else {
            alert('Hata!');
          }
        }

        loadUsers(); // İlk yükleme
      </script>
    </body>
    </html>
  `);
});

// Vercel için export
module.exports = app;
