require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const Stripe = require('stripe');

const app = express();
const PORT = process.env.PORT || 3000;
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// ── JSON File Database ──
const DB_PATH = path.join(__dirname, 'data.json');

function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) {
      return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    }
  } catch (e) {
    console.error('DB load error:', e.message);
  }
  return {
    users: [],
    emails: [],
    orders: [],
    subscriptions: [],
    stationery_inquiries: [],
    enterprise_inquiries: [],
    letters: [],
    payments: [],
    nextId: { users: 1, emails: 1, orders: 1, subscriptions: 1, stationery: 1, enterprise: 1, letters: 1, payments: 1 }
  };
}

function saveDB(data) {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error('DB save error:', e.message);
  }
}

let db = loadDB();
// Ensure payments array exists for existing DBs
if (!db.payments) { db.payments = []; }
if (!db.nextId.payments) { db.nextId.payments = 1; }

// ── Stripe Webhook (must be BEFORE express.json middleware) ──
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    if (process.env.STRIPE_WEBHOOK_SECRET && process.env.STRIPE_WEBHOOK_SECRET !== 'whsec_demo_placeholder') {
      event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } else {
      // In dev/demo mode, parse the body directly
      event = JSON.parse(req.body.toString());
    }
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  console.log('Stripe webhook event:', event.type);

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const userId = parseInt(session.metadata?.userId);
      const paymentType = session.metadata?.type;

      console.log('Payment completed:', { userId, paymentType, sessionId: session.id });

      // Record payment
      db.payments.push({
        id: db.nextId.payments++,
        stripe_session_id: session.id,
        stripe_customer_id: session.customer,
        stripe_subscription_id: session.subscription,
        user_id: userId,
        type: paymentType,
        amount_cents: session.amount_total,
        status: 'completed',
        created_at: new Date().toISOString()
      });

      if (userId) {
        const user = db.users.find(u => u.id === userId);
        if (user) {
          if (paymentType === 'single_letter') {
            // $1 per letter — add 1 letter credit
            user.letters_limit = (user.letters_limit || 0) + 1;
            if (user.plan === 'free') user.plan = 'pay_per_letter';
            user.plan_status = 'active';
          } else if (paymentType === 'individual') {
            user.plan = 'individual';
            user.plan_status = 'active';
            user.letters_limit = 10;
            user.letters_used = 0;
            user.stripe_customer_id = session.customer;
            user.stripe_subscription_id = session.subscription;
          } else if (paymentType === 'business') {
            user.plan = 'business';
            user.plan_status = 'active';
            user.letters_limit = 50;
            user.letters_used = 0;
            user.stripe_customer_id = session.customer;
            user.stripe_subscription_id = session.subscription;
          }
        }
      }
      saveDB(db);
      break;
    }

    case 'customer.subscription.deleted': {
      const sub = event.data.object;
      // Find user by stripe subscription ID and downgrade
      const user = db.users.find(u => u.stripe_subscription_id === sub.id);
      if (user) {
        user.plan = 'free';
        user.plan_status = 'cancelled';
        user.letters_limit = 0;
        user.letters_used = 0;
        user.stripe_subscription_id = null;
        saveDB(db);
        console.log('Subscription cancelled for user:', user.id);
      }
      break;
    }

    case 'invoice.payment_failed': {
      const invoice = event.data.object;
      const user = db.users.find(u => u.stripe_customer_id === invoice.customer);
      if (user) {
        user.plan_status = 'past_due';
        saveDB(db);
        console.log('Payment failed for user:', user.id);
      }
      break;
    }
  }

  res.json({ received: true });
});

// ── Middleware (after webhook route) ──
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'heartfelt-letters-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));
app.use(express.static(path.join(__dirname, 'public')));

// ── Helper Functions ──
function findUserByEmail(email) {
  return db.users.find(u => u.email === email.toLowerCase().trim()) || null;
}

function findUserById(id) {
  const u = db.users.find(u => u.id === id);
  if (!u) return null;
  const { password_hash, ...safe } = u;
  return safe;
}

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

  const existing = findUserByEmail(email);
  if (existing) {
    return res.status(409).json({ error: 'An account with this email already exists' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const user = {
      id: db.nextId.users++,
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password_hash: hash,
      plan: 'free',
      plan_status: 'active',
      letters_limit: 0,
      letters_used: 0,
      created_at: new Date().toISOString()
    };
    db.users.push(user);
    saveDB(db);

    req.session.userId = user.id;
    const { password_hash: _, ...safeUser } = user;
    res.json({ success: true, user: safeUser });
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

  const user = findUserByEmail(email);
  if (!user) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  try {
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    req.session.userId = user.id;
    const safeUser = findUserById(user.id);
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
  const user = findUserById(req.session.userId);
  res.json({ user: user || null });
});

// Use a letter credit
app.post('/api/auth/use-letter', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user || user.plan === 'free') {
    return res.status(403).json({ error: 'No active plan' });
  }
  if (user.letters_used >= user.letters_limit) {
    return res.status(403).json({ error: 'No letters remaining', letters_left: 0 });
  }
  user.letters_used++;
  saveDB(db);
  res.json({
    success: true,
    letters_used: user.letters_used,
    letters_limit: user.letters_limit,
    letters_left: user.letters_limit - user.letters_used
  });
});

// ── Stripe Payment Routes ──

// Get Stripe publishable key
app.get('/api/stripe/config', (req, res) => {
  res.json({ publishableKey: process.env.STRIPE_PUBLISHABLE_KEY });
});

// Create checkout session for $1 single letter
app.post('/api/stripe/checkout/single-letter', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Please sign in first' });
  }

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: 'Single Letter Credit',
            description: 'Download, print, or share one handwritten letter',
          },
          unit_amount: 100, // $1.00
        },
        quantity: 1,
      }],
      metadata: {
        userId: req.session.userId.toString(),
        type: 'single_letter'
      },
      success_url: `${BASE_URL}/?payment=success&type=single_letter`,
      cancel_url: `${BASE_URL}/?payment=cancelled`,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe checkout error:', err);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Create checkout session for individual subscription ($29.99/mo)
app.post('/api/stripe/checkout/individual', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Please sign in first' });
  }

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: 'Individual Plan — Monthly',
            description: '10 handwritten letters per month, premium stationery access',
          },
          unit_amount: 2999, // $29.99
          recurring: { interval: 'month' },
        },
        quantity: 1,
      }],
      metadata: {
        userId: req.session.userId.toString(),
        type: 'individual'
      },
      success_url: `${BASE_URL}/?payment=success&type=individual`,
      cancel_url: `${BASE_URL}/?payment=cancelled`,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe checkout error:', err);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Create checkout session for business subscription ($79.99/mo)
app.post('/api/stripe/checkout/business', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Please sign in first' });
  }

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: 'Business Plan — Monthly',
            description: '50 handwritten letters per month, premium stationery, priority support',
          },
          unit_amount: 7999, // $79.99
          recurring: { interval: 'month' },
        },
        quantity: 1,
      }],
      metadata: {
        userId: req.session.userId.toString(),
        type: 'business'
      },
      success_url: `${BASE_URL}/?payment=success&type=business`,
      cancel_url: `${BASE_URL}/?payment=cancelled`,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe checkout error:', err);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Cancel subscription
app.post('/api/stripe/cancel-subscription', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  const user = db.users.find(u => u.id === req.session.userId);
  if (!user || !user.stripe_subscription_id) {
    return res.status(400).json({ error: 'No active subscription found' });
  }

  try {
    await stripe.subscriptions.cancel(user.stripe_subscription_id);
    user.plan = 'free';
    user.plan_status = 'cancelled';
    user.letters_limit = 0;
    user.letters_used = 0;
    user.stripe_subscription_id = null;
    saveDB(db);
    res.json({ success: true });
  } catch (err) {
    console.error('Cancel subscription error:', err);
    res.status(500).json({ error: 'Failed to cancel subscription' });
  }
});

// Get payment history
app.get('/api/stripe/payments', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  const payments = db.payments
    .filter(p => p.user_id === req.session.userId)
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 20);
  res.json({ payments });
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
        generationConfig: { maxOutputTokens: 2048, temperature: 0.8 }
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
    db.letters.push({
      id: db.nextId.letters++,
      sender_name: sender,
      recipient_name: recipient,
      relationship, occasion, feelings,
      memories: memories || null,
      tone: tone || 'Warm',
      generated_text: letterText,
      created_at: new Date().toISOString()
    });
    saveDB(db);

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
  db.emails.push({ id: db.nextId.emails++, email, source: 'capture', created_at: new Date().toISOString() });
  saveDB(db);
  res.json({ success: true });
});

// Order a letter
app.post('/api/orders', (req, res) => {
  const { email, address, letterText, stationery } = req.body;
  if (!email || !address) {
    return res.status(400).json({ error: 'Email and address required' });
  }
  db.orders.push({
    id: db.nextId.orders++,
    email, address,
    letter_text: letterText || null,
    stationery: stationery || 'standard',
    status: 'pending',
    amount_cents: 1000,
    created_at: new Date().toISOString()
  });
  db.emails.push({ id: db.nextId.emails++, email, source: 'order', created_at: new Date().toISOString() });
  saveDB(db);
  res.json({ success: true });
});

// Subscribe (individual or business) — legacy non-Stripe
app.post('/api/subscriptions', (req, res) => {
  const { email, company, plan } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }
  const amountCents = plan === 'business' ? 7999 : 2999;
  db.subscriptions.push({
    id: db.nextId.subscriptions++,
    email, company: company || null,
    plan: plan || 'individual',
    status: 'active',
    amount_cents: amountCents,
    created_at: new Date().toISOString()
  });
  db.emails.push({ id: db.nextId.emails++, email, source: 'subscription', created_at: new Date().toISOString() });

  if (req.session.userId) {
    const user = db.users.find(u => u.id === req.session.userId);
    if (user) {
      const limit = (plan === 'business') ? 50 : 10;
      user.plan = plan || 'individual';
      user.plan_status = 'active';
      user.letters_limit = limit;
      user.letters_used = 0;
    }
  }
  saveDB(db);
  res.json({ success: true });
});

// Stationery inquiry
app.post('/api/stationery', (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }
  db.stationery_inquiries.push({ id: db.nextId.stationery++, email, created_at: new Date().toISOString() });
  db.emails.push({ id: db.nextId.emails++, email, source: 'stationery', created_at: new Date().toISOString() });
  saveDB(db);
  res.json({ success: true });
});

// Enterprise inquiry
app.post('/api/enterprise', (req, res) => {
  const { company, email, monthlyVolume } = req.body;
  if (!company || !email) {
    return res.status(400).json({ error: 'Company and email required' });
  }
  db.enterprise_inquiries.push({
    id: db.nextId.enterprise++,
    company, email,
    monthly_volume: monthlyVolume || null,
    status: 'new',
    created_at: new Date().toISOString()
  });
  db.emails.push({ id: db.nextId.emails++, email, source: 'enterprise', created_at: new Date().toISOString() });
  saveDB(db);
  res.json({ success: true });
});

// ── Admin Stats ──
app.get('/api/admin/stats', (req, res) => {
  res.json({
    totalUsers: db.users.length,
    totalEmails: db.emails.length,
    totalOrders: db.orders.length,
    totalSubscriptions: db.subscriptions.length,
    activeSubscriptions: db.subscriptions.filter(s => s.status === 'active').length,
    totalLettersGenerated: db.letters.length,
    totalPayments: db.payments.length,
    totalRevenueCents: db.payments.reduce((sum, p) => sum + (p.amount_cents || 0), 0),
    enterpriseInquiries: db.enterprise_inquiries.length,
    recentOrders: db.orders.slice(-10).reverse(),
    recentPayments: db.payments.slice(-10).reverse(),
    recentEmails: db.emails.slice(-10).reverse()
  });
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
  saveDB(db);
  process.exit(0);
});
