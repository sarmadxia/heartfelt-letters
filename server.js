require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ──
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'heartfelt-letters-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
  }
}));
app.use(express.static(path.join(__dirname, 'public')));

// ── Database Setup ──
const db = new Database(path.join(__dirname, 'heartfelt.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    plan TEXT DEFAULT 'free',
    plan_status TEXT DEFAULT 'active',
    letters_limit INTEGER DEFAULT 0,
    letters_used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    source TEXT DEFAULT 'capture',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    address TEXT NOT NULL,
    letter_text TEXT,
    stationery TEXT DEFAULT 'standard',
    status TEXT DEFAULT 'pending',
    amount_cents INTEGER DEFAULT 1000,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    company TEXT,
    plan TEXT NOT NULL DEFAULT 'individual',
    status TEXT DEFAULT 'active',
    amount_cents INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS stationery_inquiries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS enterprise_inquiries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company TEXT NOT NULL,
    email TEXT NOT NULL,
    monthly_volume INTEGER,
    status TEXT DEFAULT 'new',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS letters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_name TEXT,
    recipient_name TEXT,
    relationship TEXT,
    occasion TEXT,
    feelings TEXT,
    memories TEXT,
    tone TEXT,
    generated_text TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ── Migrations (add columns if they don't exist) ──
try {
  db.exec(`ALTER TABLE users ADD COLUMN letters_limit INTEGER DEFAULT 0`);
} catch (e) { /* column already exists */ }
try {
  db.exec(`ALTER TABLE users ADD COLUMN letters_used INTEGER DEFAULT 0`);
} catch (e) { /* column already exists */ }

// ── Prepared Statements ──
const insertUser = db.prepare('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)');
const findUserByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const findUserById = db.prepare('SELECT id, name, email, plan, plan_status, letters_limit, letters_used, created_at FROM users WHERE id = ?');
const updateUserPlan = db.prepare('UPDATE users SET plan = ?, plan_status = ?, letters_limit = ?, letters_used = 0 WHERE id = ?');
const incrementLettersUsed = db.prepare('UPDATE users SET letters_used = letters_used + 1 WHERE id = ?');
const insertEmail = db.prepare('INSERT INTO emails (email, source) VALUES (?, ?)');
const insertOrder = db.prepare('INSERT INTO orders (email, address, letter_text, stationery) VALUES (?, ?, ?, ?)');
const insertSubscription = db.prepare('INSERT INTO subscriptions (email, company, plan, amount_cents) VALUES (?, ?, ?, ?)');
const insertStationeryInquiry = db.prepare('INSERT INTO stationery_inquiries (email) VALUES (?)');
const insertEnterprise = db.prepare('INSERT INTO enterprise_inquiries (company, email, monthly_volume) VALUES (?, ?, ?)');
const insertLetter = db.prepare(`
  INSERT INTO letters (sender_name, recipient_name, relationship, occasion, feelings, memories, tone, generated_text)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

// ── Auth Routes ──

// Sign up
app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  // Check if email already exists
  const existing = findUserByEmail.get(email.toLowerCase().trim());
  if (existing) {
    return res.status(409).json({ error: 'An account with this email already exists' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const result = insertUser.run(name.trim(), email.toLowerCase().trim(), hash);
    const user = findUserById.get(result.lastInsertRowid);

    req.session.userId = user.id;
    res.json({ success: true, user });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

// Log in
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const user = findUserByEmail.get(email.toLowerCase().trim());
  if (!user) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  try {
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    req.session.userId = user.id;
    const safeUser = findUserById.get(user.id);
    res.json({ success: true, user: safeUser });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Log out
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

// Get current user
app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) {
    return res.json({ user: null });
  }
  const user = findUserById.get(req.session.userId);
  if (!user) {
    return res.json({ user: null });
  }
  res.json({ user });
});

// Use a letter credit
app.post('/api/auth/use-letter', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  const user = findUserById.get(req.session.userId);
  if (!user || user.plan === 'free') {
    return res.status(403).json({ error: 'No active plan' });
  }
  if (user.letters_used >= user.letters_limit) {
    return res.status(403).json({ error: 'No letters remaining', letters_left: 0 });
  }
  incrementLettersUsed.run(req.session.userId);
  const updated = findUserById.get(req.session.userId);
  res.json({
    success: true,
    letters_used: updated.letters_used,
    letters_limit: updated.letters_limit,
    letters_left: updated.letters_limit - updated.letters_used
  });
});

// ── Routes ──

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Generate letter (Gemini API proxy)
app.post('/api/generate-letter', async (req, res) => {
  const { sender, recipient, relationship, occasion, feelings, memories, tone } = req.body;

  if (!sender || !recipient || !relationship || !occasion || !feelings) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const prompt = `Write a beautiful, personal handwritten letter from ${sender} to ${recipient}. They are ${relationship}.
Occasion: ${occasion}
What they want to express: ${feelings}
${memories ? `Specific memories or details to include: ${memories}` : ''}
Desired tone: ${tone || 'Warm'}

Instructions:
- Write in first person as ${sender}
- Address it to ${recipient} at the start
- Sign off warmly as ${sender}
- Make it feel genuinely personal, not generic
- Use natural, flowing language as if handwritten
- Length: 150–280 words
- Do NOT add any commentary, preamble, or quotation marks — just the letter itself`;

  try {
    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`;

    const response = await fetch(geminiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { maxOutputTokens: 1000, temperature: 0.8 }
      })
    });

    if (!response.ok) {
      const errBody = await response.text();
      console.error('Gemini API error:', response.status, errBody);
      return res.status(response.status).json({ error: 'Letter generation failed' });
    }

    const data = await response.json();
    const letterText = data.candidates?.[0]?.content?.parts?.[0]?.text;

    if (!letterText) {
      return res.status(500).json({ error: 'No text in API response' });
    }

    // Save to database
    try {
      insertLetter.run(sender, recipient, relationship, occasion, feelings, memories || null, tone || 'Warm', letterText);
    } catch (dbErr) {
      console.error('DB insert error (non-fatal):', dbErr.message);
    }

    res.json({ letter: letterText });
  } catch (err) {
    console.error('Generate letter error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Email capture
app.post('/api/email-capture', (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email required' });
  }
  try {
    const result = insertEmail.run(email, 'capture');
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (err) {
    console.error('Email capture error:', err);
    res.status(500).json({ error: 'Failed to save email' });
  }
});

// Order a letter
app.post('/api/orders', (req, res) => {
  const { email, address, letterText, stationery } = req.body;
  if (!email || !address) {
    return res.status(400).json({ error: 'Email and address required' });
  }
  try {
    const result = insertOrder.run(email, address, letterText || null, stationery || 'standard');
    try { insertEmail.run(email, 'order'); } catch (e) { /* duplicate ok */ }
    res.json({ success: true, orderId: result.lastInsertRowid });
  } catch (err) {
    console.error('Order error:', err);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// Subscribe (individual or business)
app.post('/api/subscriptions', (req, res) => {
  const { email, company, plan } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }
  const amountCents = plan === 'business' ? 7999 : 2999;
  try {
    const result = insertSubscription.run(email, company || null, plan || 'individual', amountCents);
    try { insertEmail.run(email, 'subscription'); } catch (e) { /* duplicate ok */ }

    // If user is logged in, upgrade their plan with letter limits
    if (req.session.userId) {
      // Individual: 10 letters/month, Business: 50 letters/month
      const limit = (plan === 'business') ? 50 : 10;
      updateUserPlan.run(plan || 'individual', 'active', limit, req.session.userId);
    }

    res.json({ success: true, subscriptionId: result.lastInsertRowid });
  } catch (err) {
    console.error('Subscription error:', err);
    res.status(500).json({ error: 'Failed to create subscription' });
  }
});

// Stationery inquiry
app.post('/api/stationery', (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }
  try {
    const result = insertStationeryInquiry.run(email);
    try { insertEmail.run(email, 'stationery'); } catch (e) { /* duplicate ok */ }
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (err) {
    console.error('Stationery inquiry error:', err);
    res.status(500).json({ error: 'Failed to save inquiry' });
  }
});

// Enterprise inquiry
app.post('/api/enterprise', (req, res) => {
  const { company, email, monthlyVolume } = req.body;
  if (!company || !email) {
    return res.status(400).json({ error: 'Company and email required' });
  }
  try {
    const result = insertEnterprise.run(company, email, monthlyVolume || null);
    try { insertEmail.run(email, 'enterprise'); } catch (e) { /* duplicate ok */ }
    res.json({ success: true, inquiryId: result.lastInsertRowid });
  } catch (err) {
    console.error('Enterprise inquiry error:', err);
    res.status(500).json({ error: 'Failed to save inquiry' });
  }
});

// ── Admin Routes (basic, no auth — add auth for production) ──

app.get('/api/admin/stats', (req, res) => {
  try {
    const stats = {
      totalUsers: db.prepare('SELECT COUNT(*) as count FROM users').get().count,
      totalEmails: db.prepare('SELECT COUNT(*) as count FROM emails').get().count,
      totalOrders: db.prepare('SELECT COUNT(*) as count FROM orders').get().count,
      totalSubscriptions: db.prepare('SELECT COUNT(*) as count FROM subscriptions').get().count,
      activeSubscriptions: db.prepare("SELECT COUNT(*) as count FROM subscriptions WHERE status = 'active'").get().count,
      totalLettersGenerated: db.prepare('SELECT COUNT(*) as count FROM letters').get().count,
      enterpriseInquiries: db.prepare('SELECT COUNT(*) as count FROM enterprise_inquiries').get().count,
      recentOrders: db.prepare('SELECT * FROM orders ORDER BY created_at DESC LIMIT 10').all(),
      recentEmails: db.prepare('SELECT * FROM emails ORDER BY created_at DESC LIMIT 10').all(),
    };
    res.json(stats);
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// ── Catch-all: serve index.html ──
app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start Server ──
app.listen(PORT, () => {
  console.log(`\n  ✦ Heartfelt Letters server running at http://localhost:${PORT}\n`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  db.close();
  process.exit(0);
});
