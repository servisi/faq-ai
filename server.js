// server.js
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const Stripe = require('stripe');
const OpenAI = require('openai');
const axios = require('axios');
const cors = require('cors');

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors()); // CORS'u etkinleştir

mongoose.connect(process.env.MONGO_URI);

const UserSchema = new mongoose.Schema({
  email: String,
  credits: { type: Number, default: 400 },
  lastReset: { type: Date, default: Date.now },
  plan: { type: String, default: 'free' },
  expirationDate: { type: Date, default: null }
});
const User = mongoose.model('User', UserSchema);

const openai = new OpenAI({
  apiKey: process.env.DEEPSEEK_API_KEY,
  baseURL: 'https://api.deepseek.com/v1'
});
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const JWT_SECRET = process.env.JWT_SECRET;
const SERPAPI_KEY = process.env.SERPAPI_KEY;

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

// Kayıt Endpoint
app.post('/register', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const existing = await User.findOne({ email });
  if (existing) return res.status(400).json({ error: 'User exists' });
  const user = new User({ email });
  await user.save();
  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1y' });
  res.json({ token });
});

// User Info Endpoint
app.get('/user-info', authenticate, async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const now = new Date();
  let remainingDays = 0;
  if (user.plan === 'pro' && user.expirationDate) {
    remainingDays = Math.max(0, Math.ceil((user.expirationDate - now) / (1000 * 60 * 60 * 24)));
  }

  if (user.plan === 'free') {
    if (now.getMonth() !== user.lastReset.getMonth() || now.getFullYear() !== user.lastReset.getFullYear()) {
      user.credits = 400;
      user.lastReset = now;
      await user.save();
    }
  }

  res.json({
    plan: user.plan === 'free' ? 'Ücretsiz Sürüm' : 'Pro Sürüm',
    credits: user.plan === 'pro' ? 'Sınırsız' : user.credits,
    remainingDays: remainingDays
  });
});

// FAQ Üret Endpoint
app.post('/api/generate-faq', authenticate, async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (user.plan === 'free') {
    const now = new Date();
    if (now.getMonth() !== user.lastReset.getMonth() || now.getFullYear() !== user.lastReset.getFullYear()) {
      user.credits = 400;
      user.lastReset = now;
      await user.save();
    }
    if (user.credits <= 0) {
      return res.status(402).json({ error: 'no_credits' });
    }
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
      model: 'deepseek-chat',
      messages: [{ role: 'user', content: prompt }],
    });
    const faqs = JSON.parse(completion.choices[0].message.content).faqs;

    if (user.plan === 'free') {
      user.credits -= 1;
      await user.save();
    }

    res.json({ faqs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Kredi Satın Al
app.post('/buy-credits', authenticate, async (req, res) => {
  const { amount, return_url } = req.body;
  const baseUrl = process.env.VERCEL_URL || 'http://localhost:3000';
  const encodedReturnUrl = encodeURIComponent(return_url || `${baseUrl}/success`);
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: `${amount} Credits` },
        unit_amount: 500,
      },
      quantity: 1,
    }],
    mode: 'payment',
    success_url: `${baseUrl}/success?session_id={CHECKOUT_SESSION_ID}&return_url=${encodedReturnUrl}`,
    cancel_url: `${baseUrl}/cancel?return_url=${encodedReturnUrl}`,
    metadata: { userId: req.userId.toString(), type: 'credits', amount }
  });
  res.json({ id: session.id });
});

// Pro Üyelik Yükselt
app.post('/upgrade-pro', authenticate, async (req, res) => {
  const { return_url } = req.body;
  const baseUrl = process.env.VERCEL_URL || 'http://localhost:3000';
  const encodedReturnUrl = encodeURIComponent(return_url || `${baseUrl}/success`);
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: 'Pro Üyelik (1 Ay)' },
        unit_amount: 1000,
      },
      quantity: 1,
    }],
    mode: 'payment',
    success_url: `${baseUrl}/success?session_id={CHECKOUT_SESSION_ID}&return_url=${encodedReturnUrl}`,
    cancel_url: `${baseUrl}/cancel?return_url=${encodedReturnUrl}`,
    metadata: { userId: req.userId.toString(), type: 'pro' }
  });
  res.json({ id: session.id });
});

// Stripe Webhook
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.metadata.userId;
    const user = await User.findById(userId);
    if (user) {
      if (session.metadata.type === 'credits') {
        user.credits += parseInt(session.metadata.amount);
      } else if (session.metadata.type === 'pro') {
        user.plan = 'pro';
        user.expirationDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        user.credits = -1;
      }
      await user.save();
    }
  }
  res.json({ received: true });
});

// Success Route
app.get('/success', async (req, res) => {
  const returnUrl = req.query.return_url ? decodeURIComponent(req.query.return_url) : null;
  if (returnUrl) {
    res.redirect(returnUrl);
  } else {
    res.send('<h1>Ödeme Başarılı! Krediniz veya üyeliğiniz eklendi. Lütfen WordPress admin panelinize dönün ve ayarlar sayfasını yenileyin.</h1>');
  }
});

// Cancel Route
app.get('/cancel', (req, res) => {
  const returnUrl = req.query.return_url ? decodeURIComponent(req.query.return_url) : null;
  if (returnUrl) {
    res.redirect(returnUrl);
  } else {
    res.send('<h1>Ödeme İptal Edildi. Lütfen tekrar deneyin veya WordPress admin panelinize dönün.</h1>');
  }
});

// Vercel için export (serverless)
module.exports = app;// server.js
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const Stripe = require('stripe');
const OpenAI = require('openai');
const axios = require('axios');
const cors = require('cors');

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors()); // CORS'u etkinleştir

mongoose.connect(process.env.MONGO_URI);

const UserSchema = new mongoose.Schema({
  email: String,
  credits: { type: Number, default: 400 },
  lastReset: { type: Date, default: Date.now },
  plan: { type: String, default: 'free' },
  expirationDate: { type: Date, default: null }
});
const User = mongoose.model('User', UserSchema);

const openai = new OpenAI({
  apiKey: process.env.DEEPSEEK_API_KEY,
  baseURL: 'https://api.deepseek.com/v1'
});
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const JWT_SECRET = process.env.JWT_SECRET;
const SERPAPI_KEY = process.env.SERPAPI_KEY;

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

// Kayıt Endpoint
app.post('/register', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const existing = await User.findOne({ email });
  if (existing) return res.status(400).json({ error: 'User exists' });
  const user = new User({ email });
  await user.save();
  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1y' });
  res.json({ token });
});

// User Info Endpoint
app.get('/user-info', authenticate, async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const now = new Date();
  let remainingDays = 0;
  if (user.plan === 'pro' && user.expirationDate) {
    remainingDays = Math.max(0, Math.ceil((user.expirationDate - now) / (1000 * 60 * 60 * 24)));
  }

  if (user.plan === 'free') {
    if (now.getMonth() !== user.lastReset.getMonth() || now.getFullYear() !== user.lastReset.getFullYear()) {
      user.credits = 400;
      user.lastReset = now;
      await user.save();
    }
  }

  res.json({
    plan: user.plan === 'free' ? 'Ücretsiz Sürüm' : 'Pro Sürüm',
    credits: user.plan === 'pro' ? 'Sınırsız' : user.credits,
    remainingDays: remainingDays
  });
});

// FAQ Üret Endpoint
app.post('/api/generate-faq', authenticate, async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (user.plan === 'free') {
    const now = new Date();
    if (now.getMonth() !== user.lastReset.getMonth() || now.getFullYear() !== user.lastReset.getFullYear()) {
      user.credits = 400;
      user.lastReset = now;
      await user.save();
    }
    if (user.credits <= 0) {
      return res.status(402).json({ error: 'no_credits' });
    }
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
      model: 'deepseek-chat',
      messages: [{ role: 'user', content: prompt }],
    });
    const faqs = JSON.parse(completion.choices[0].message.content).faqs;

    if (user.plan === 'free') {
      user.credits -= 1;
      await user.save();
    }

    res.json({ faqs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Kredi Satın Al
app.post('/buy-credits', authenticate, async (req, res) => {
  const { amount, return_url } = req.body;
  const baseUrl = process.env.VERCEL_URL || 'http://localhost:3000';
  const encodedReturnUrl = encodeURIComponent(return_url || `${baseUrl}/success`);
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: `${amount} Credits` },
        unit_amount: 500,
      },
      quantity: 1,
    }],
    mode: 'payment',
    success_url: `${baseUrl}/success?session_id={CHECKOUT_SESSION_ID}&return_url=${encodedReturnUrl}`,
    cancel_url: `${baseUrl}/cancel?return_url=${encodedReturnUrl}`,
    metadata: { userId: req.userId.toString(), type: 'credits', amount }
  });
  res.json({ id: session.id });
});

// Pro Üyelik Yükselt
app.post('/upgrade-pro', authenticate, async (req, res) => {
  const { return_url } = req.body;
  const baseUrl = process.env.VERCEL_URL || 'http://localhost:3000';
  const encodedReturnUrl = encodeURIComponent(return_url || `${baseUrl}/success`);
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: 'Pro Üyelik (1 Ay)' },
        unit_amount: 1000,
      },
      quantity: 1,
    }],
    mode: 'payment',
    success_url: `${baseUrl}/success?session_id={CHECKOUT_SESSION_ID}&return_url=${encodedReturnUrl}`,
    cancel_url: `${baseUrl}/cancel?return_url=${encodedReturnUrl}`,
    metadata: { userId: req.userId.toString(), type: 'pro' }
  });
  res.json({ id: session.id });
});

// Stripe Webhook
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.metadata.userId;
    const user = await User.findById(userId);
    if (user) {
      if (session.metadata.type === 'credits') {
        user.credits += parseInt(session.metadata.amount);
      } else if (session.metadata.type === 'pro') {
        user.plan = 'pro';
        user.expirationDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        user.credits = -1;
      }
      await user.save();
    }
  }
  res.json({ received: true });
});

// Success Route
app.get('/success', async (req, res) => {
  const returnUrl = req.query.return_url ? decodeURIComponent(req.query.return_url) : null;
  if (returnUrl) {
    res.redirect(returnUrl);
  } else {
    res.send('<h1>Ödeme Başarılı! Krediniz veya üyeliğiniz eklendi. Lütfen WordPress admin panelinize dönün ve ayarlar sayfasını yenileyin.</h1>');
  }
});

// Cancel Route
app.get('/cancel', (req, res) => {
  const returnUrl = req.query.return_url ? decodeURIComponent(req.query.return_url) : null;
  if (returnUrl) {
    res.redirect(returnUrl);
  } else {
    res.send('<h1>Ödeme İptal Edildi. Lütfen tekrar deneyin veya WordPress admin panelinize dönün.</h1>');
  }
});

// Vercel için export (serverless)
module.exports = app;
