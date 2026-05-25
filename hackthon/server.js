// server.js — SentinelAI Backend (Fixed & Hardened)
// Run:
//   npm install express cors helmet express-rate-limit @anthropic-ai/sdk
//   node server.js
//
// Requires:
//   Node.js 18+
//   Environment:
//     ANTHROPIC_API_KEY=your_key
//     FRONTEND_ORIGIN=http://localhost:3000

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import Anthropic from '@anthropic-ai/sdk';
import { fileURLToPath } from 'url';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs';

// ────────────────────────────────────────────────────────────────────────────
// Setup
// ────────────────────────────────────────────────────────────────────────────

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3001;

// ────────────────────────────────────────────────────────────────────────────
// Environment Validation
// ────────────────────────────────────────────────────────────────────────────

if (!process.env.ANTHROPIC_API_KEY) {
  console.error('❌ Missing ANTHROPIC_API_KEY');
  process.exit(1);
}

// ────────────────────────────────────────────────────────────────────────────
// Anthropic Client
// ────────────────────────────────────────────────────────────────────────────

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});

// ────────────────────────────────────────────────────────────────────────────
// Middleware
// ────────────────────────────────────────────────────────────────────────────

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN || 'http://localhost:3000',
  })
);

app.use(express.json({ limit: '2mb' }));

// ────────────────────────────────────────────────────────────────────────────
// Rate Limiting
// ────────────────────────────────────────────────────────────────────────────

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
});

const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  message: {
    error: 'AI rate limit exceeded. Try again later.',
  },
});

app.use('/api', apiLimiter);
app.use('/api/ai', aiLimiter);

// ────────────────────────────────────────────────────────────────────────────
// Demo User Store
// NOTE: Replace with DB in production
// ────────────────────────────────────────────────────────────────────────────

const USERS = [
  {
    id: 'u1',
    email: 'admin@example.com',
    password: 'Admin123!',
    role: 'admin',
    name: 'Admin',
  },
  {
    id: 'u2',
    email: 'admin@yourcompany.com',
    password: 'Admin123!',
    role: 'admin',
    name: 'SysAdmin',
  },
  {
    id: 'u3',
    email: 'analyst@corp.com',
    password: 'Analyst1!',
    role: 'client',
    name: 'Analyst',
  },
  {
    id: 'u4',
    email: 'client@example.com',
    password: 'Client123!',
    role: 'client',
    name: 'Client',
  },
];

// ────────────────────────────────────────────────────────────────────────────
// Session Store
// ────────────────────────────────────────────────────────────────────────────

const sessions = new Map();

// Secure token generation
function generateToken() {
  return crypto.randomBytes(48).toString('hex');
}

function createSession(userId) {
  const token = generateToken();

  sessions.set(token, {
    userId,
    expiresAt: Date.now() + 8 * 60 * 60 * 1000,
  });

  return token;
}

function getSessionUser(token) {
  if (!token) return null;

  const session = sessions.get(token);

  if (!session) return null;

  if (session.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }

  return USERS.find((u) => u.id === session.userId) || null;
}

// Cleanup expired sessions every hour
setInterval(() => {
  const now = Date.now();

  for (const [token, session] of sessions.entries()) {
    if (session.expiresAt < now) {
      sessions.delete(token);
    }
  }
}, 60 * 60 * 1000);

// ────────────────────────────────────────────────────────────────────────────
// Auth Middleware
// ────────────────────────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');

  const user = getSessionUser(token);

  if (!user) {
    return res.status(401).json({
      error: 'Unauthorized',
    });
  }

  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');

  const user = getSessionUser(token);

  if (!user) {
    return res.status(401).json({
      error: 'Unauthorized',
    });
  }

  if (user.role !== 'admin') {
    return res.status(403).json({
      error: 'Admin access required',
    });
  }

  req.user = user;
  next();
}

// ────────────────────────────────────────────────────────────────────────────
// Auth Routes
// ────────────────────────────────────────────────────────────────────────────

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({
      error: 'Email and password required',
    });
  }

  const user = USERS.find(
    (u) => u.email.toLowerCase() === email.toLowerCase().trim()
  );

  if (!user || user.password !== password) {
    return res.status(401).json({
      error: 'Invalid email or password',
    });
  }

  const token = createSession(user.id);

  res.json({
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      initials: user.name[0].toUpperCase(),
    },
  });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  sessions.delete(token);

  res.json({
    ok: true,
  });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const { id, name, email, role } = req.user;

  res.json({
    id,
    name,
    email,
    role,
    initials: name[0].toUpperCase(),
  });
});

// ────────────────────────────────────────────────────────────────────────────
// AI Analysis Route
// ────────────────────────────────────────────────────────────────────────────

app.post('/api/ai/analyze', requireAuth, async (req, res) => {
  try {
    const {
      messages = [],
      metrics = {},
      threats = [],
    } = req.body;

    const threatSummary = threats
      .slice(0, 5)
      .map(
        (t) =>
          `- ${t.sev?.toUpperCase() || 'UNKNOWN'}: ${t.title || 'Untitled'}`
      )
      .join('\n');

    const systemPrompt = `
You are SentinelAI, an expert cybersecurity analyst AI.

Current security metrics:
- Critical threats: ${metrics.critical ?? 0}
- High severity events: ${metrics.high ?? 0}
- False positives filtered: ${metrics.fp ?? 0}
- Total events analyzed: ${metrics.total ?? 0}

Recent threats:
${threatSummary || 'No threats recorded.'}

Keep responses concise and technical.
`;

    const response = await anthropic.messages.create({
      model: 'claude-3-5-sonnet-latest',
      max_tokens: 1000,
      system: systemPrompt,
      messages: messages.slice(-6),
    });

    const reply =
      response.content?.[0]?.text ||
      'Unable to analyze at this time.';

    res.json({ reply });
  } catch (err) {
    console.error('[AI ERROR]', err);

    res.status(500).json({
      error: 'AI analysis unavailable',
      details: err.message,
    });
  }
});

// ────────────────────────────────────────────────────────────────────────────
// False Positive Filter
// ────────────────────────────────────────────────────────────────────────────

app.post('/api/threats/filter-fp', requireAuth, async (req, res) => {
  try {
    const { threats = [] } = req.body;

    if (!threats.length) {
      return res.json({
        results: [],
      });
    }

    const prompt = `
You are a cybersecurity false-positive detector.

Analyze these events:
${JSON.stringify(threats.slice(0, 10), null, 2)}

Return ONLY valid JSON:
[
  {
    "index": 0,
    "fp": false,
    "reason": "Reason here"
  }
]
`;

    const response = await anthropic.messages.create({
      model: 'claude-3-5-sonnet-latest',
      max_tokens: 600,
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
    });

    const raw = response.content?.[0]?.text || '[]';

    let results = [];

    try {
      results = JSON.parse(
        raw.replace(/```json|```/g, '').trim()
      );
    } catch (parseErr) {
      console.error('JSON Parse Error:', parseErr.message);

      return res.status(500).json({
        error: 'Invalid AI response format',
      });
    }

    res.json({ results });
  } catch (err) {
    console.error('[FP FILTER ERROR]', err);

    res.status(500).json({
      error: 'FP filter unavailable',
    });
  }
});

// ────────────────────────────────────────────────────────────────────────────
// Threat Explanation
// ────────────────────────────────────────────────────────────────────────────

app.post('/api/threats/explain', requireAuth, async (req, res) => {
  try {
    const { threat } = req.body;

    if (!threat) {
      return res.status(400).json({
        error: 'Threat object required',
      });
    }

    const prompt = `
Explain this security event briefly:

Title: ${threat.title}
Severity: ${threat.sev}
Category: ${threat.cat}
Source IP: ${threat.ip}
Country: ${threat.country}
Path/Port: ${threat.path}
Target User: ${threat.user}
`;

    const response = await anthropic.messages.create({
      model: 'claude-3-5-sonnet-latest',
      max_tokens: 300,
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
    });

    res.json({
      explanation:
        response.content?.[0]?.text ||
        'Unable to generate explanation.',
    });
  } catch (err) {
    console.error('[EXPLAIN ERROR]', err);

    res.status(500).json({
      error: 'Explanation unavailable',
    });
  }
});

// ────────────────────────────────────────────────────────────────────────────
// Geo Intelligence
// ────────────────────────────────────────────────────────────────────────────

app.get('/api/geo/intelligence', requireAuth, (req, res) => {
  const base = [
    {
      flag: '🇷🇺',
      name: 'Russia',
      attacks: 247,
      risk: 'critical',
    },
    {
      flag: '🇨🇳',
      name: 'China',
      attacks: 189,
      risk: 'critical',
    },
    {
      flag: '🇧🇷',
      name: 'Brazil',
      attacks: 134,
      risk: 'high',
    },
  ];

  res.json({
    countries: base,
    generatedAt: new Date().toISOString(),
  });
});

// ────────────────────────────────────────────────────────────────────────────
// Realtime Alerts
// ────────────────────────────────────────────────────────────────────────────

app.post('/api/alerts/realtime', requireAdmin, (req, res) => {
  const { alert } = req.body;

  if (!alert) {
    return res.status(400).json({
      error: 'Alert payload required',
    });
  }

  console.log('[ALERT]', JSON.stringify(alert));

  res.json({
    received: true,
    alertId: `ALT-${Date.now()}`,
  });
});

// ────────────────────────────────────────────────────────────────────────────
// Admin Routes
// ────────────────────────────────────────────────────────────────────────────

app.get('/api/admin/users', requireAdmin, (req, res) => {
  res.json({
    users: USERS.map(({ password, ...u }) => u),
    total: USERS.length,
  });
});

app.get('/api/admin/sessions', requireAdmin, (req, res) => {
  res.json({
    activeSessions: sessions.size,
  });
});

// ────────────────────────────────────────────────────────────────────────────
// Health Check
// ────────────────────────────────────────────────────────────────────────────

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// ────────────────────────────────────────────────────────────────────────────
// Static Frontend
// ────────────────────────────────────────────────────────────────────────────

const publicDir = path.join(__dirname, 'public');
const indexPath = path.join(publicDir, 'index.html');

app.use(express.static(publicDir));

app.use((req, res) => {
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).json({
      error: 'Frontend not built',
    });
  }
});

// ────────────────────────────────────────────────────────────────────────────
// Start Server
// ────────────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`
🛡️ SentinelAI Backend Running
🌐 http://localhost:${PORT}
✅ Anthropic API Connected
`);
});