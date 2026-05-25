// ── Global State ──────────────────────────────────────────────────────────
const state = {
  threats: [],
  authEvents: [],
  logs: [],
  geoData: {},
  metrics: { critical: 0, high: 0, fp: 0, total: 0, authFailed: 0, authSusp: 0, authMfa: 0 },
  logPaused: false,
  currentThreat: null,
  user: null,
  aiMessages: [],
  trendData: new Array(24).fill(0),
  alertCount: 0,
  eventRate: 0
};

// ── Threat Templates ──────────────────────────────────────────────────────
const threatTemplates = [
  { title: 'SQL Injection Attempt',        sev: 'critical', cat: 'Injection',        ip: '185.220.101.47', country: '🇷🇺 Russia',      user: 'anonymous',         path: '/api/users?id=1 OR 1=1',  fp: false },
  { title: 'Brute Force Attack — SSH',     sev: 'critical', cat: 'Credential Attack', ip: '45.33.32.156',   country: '🇨🇳 China',       user: 'root',              path: 'SSH:22',                  fp: false },
  { title: 'XSS Payload Detected',         sev: 'high',     cat: 'Injection',        ip: '103.21.244.0',   country: '🇧🇷 Brazil',      user: 'guest',             path: '/search?q=<script>',      fp: false },
  { title: 'Port Scan Detected',           sev: 'medium',   cat: 'Reconnaissance',   ip: '198.51.100.23',  country: '🇩🇪 Germany',     user: '-',                 path: 'TCP 1-65535',             fp: true  },
  { title: 'Suspicious Login — New Country', sev: 'high',   cat: 'Account Takeover', ip: '41.90.64.0',     country: '🇳🇬 Nigeria',     user: 'admin@corp.com',    path: 'HTTPS /login',            fp: false },
  { title: 'DDoS Spike Detected',          sev: 'critical', cat: 'Availability',     ip: '0.0.0.0/0',      country: '🌐 Multiple',     user: '-',                 path: '/',                       fp: false },
  { title: 'Path Traversal Attempt',       sev: 'high',     cat: 'Injection',        ip: '91.108.4.0',     country: '🇮🇷 Iran',        user: 'anonymous',         path: '/../../../etc/passwd',    fp: false },
  { title: 'Unusual Data Exfiltration',    sev: 'critical', cat: 'Data Breach',      ip: '10.0.0.55',      country: '🏠 Internal',     user: 'john.doe@corp.com', path: '/api/export?all=true',    fp: false },
  { title: 'Botnet C2 Callback',           sev: 'critical', cat: 'Malware',          ip: '51.15.62.101',   country: '🇫🇷 France',      user: '-',                 path: 'TCP 4444',                fp: false },
  { title: 'API Rate Limit Exceeded',      sev: 'low',      cat: 'Availability',     ip: '203.0.113.45',   country: '🇮🇳 India',       user: 'api-user',          path: '/api/v2/data',            fp: true  },
  { title: 'CSRF Token Mismatch',          sev: 'medium',   cat: 'Session',          ip: '172.16.0.100',   country: '🏠 Internal',     user: 'user@corp.com',     path: '/profile/update',         fp: true  },
  { title: 'Privilege Escalation Attempt', sev: 'critical', cat: 'Lateral Movement', ip: '10.0.1.23',      country: '🏠 Internal',     user: 'dev-account',       path: '/admin/grants',           fp: false },
  { title: 'Malicious File Upload',        sev: 'high',     cat: 'Malware',          ip: '89.248.167.131', country: '🇳🇱 Netherlands', user: 'anonymous',         path: '/upload shell.php',       fp: false },
  { title: 'DNS Tunneling Detected',       sev: 'high',     cat: 'Exfiltration',     ip: '10.0.0.88',      country: '🏠 Internal',     user: '-',                 path: 'DNS TXT queries',         fp: false },
];

// ── Geo Data ──────────────────────────────────────────────────────────────
const geoCountries = [
  { flag: '🇷🇺', name: 'Russia',        attacks: 247, ip: '185.220.x.x' },
  { flag: '🇨🇳', name: 'China',         attacks: 189, ip: '45.33.x.x'   },
  { flag: '🇧🇷', name: 'Brazil',        attacks: 134, ip: '103.21.x.x'  },
  { flag: '🇳🇱', name: 'Netherlands',   attacks: 98,  ip: '89.248.x.x'  },
  { flag: '🇺🇸', name: 'United States', attacks: 76,  ip: '198.51.x.x'  },
  { flag: '🇩🇪', name: 'Germany',       attacks: 54,  ip: '91.108.x.x'  },
  { flag: '🇮🇷', name: 'Iran',          attacks: 43,  ip: '45.142.x.x'  },
  { flag: '🇳🇬', name: 'Nigeria',       attacks: 38,  ip: '41.90.x.x'   },
];

// ── Log Templates ─────────────────────────────────────────────────────────
const logTemplates = [
  { level: 'err',  msg: 'AUTH_FAIL user=root ip=185.220.101.47 attempts=47'                    },
  { level: 'err',  msg: 'WAF_BLOCK rule=SQL_INJ ip=45.33.32.156 path=/api/users'               },
  { level: 'warn', msg: 'RATE_LIMIT exceeded ip=203.0.113.45 req=1052/min'                     },
  { level: 'info', msg: 'SESSION_CREATE user=alice@corp.com ip=10.0.1.5 mfa=true'              },
  { level: 'err',  msg: 'PRIV_ESC_ATTEMPT user=dev001 target=/admin/grants'                    },
  { level: 'ok',   msg: 'SCAN_COMPLETE threats=3 false_positives=12 blocked=3'                 },
  { level: 'warn', msg: 'GEO_ANOMALY user=john@corp.com prev=IN curr=NG delta=12h'             },
  { level: 'info', msg: 'MFA_CHALLENGE user=bob@corp.com method=TOTP result=PASS'              },
  { level: 'err',  msg: 'C2_CALLBACK detected src=10.0.0.88 dst=51.15.62.101:4444'            },
  { level: 'warn', msg: 'DATA_VOLUME anomaly user=jane@corp.com egress=2.4GB normal=50MB'      },
  { level: 'ok',   msg: 'FP_FILTERED rule=PORT_SCAN confidence=0.94 suppressed=1'             },
  { level: 'err',  msg: 'XSS_DETECTED url=/search payload=<img/onerror=...> ip=103.21.244.0'  },
];

// ── Auth Event Templates ──────────────────────────────────────────────────
const authTemplates = [
  { title: 'Failed Login — Too Many Attempts',    sev: 'critical', user: 'root',           ip: '185.220.101.47', detail: '47 attempts in 2 min',          fp: false },
  { title: 'Successful Login from New Location',  sev: 'high',     user: 'admin@corp.com', ip: '41.90.64.0',     detail: 'Country: Nigeria (new)',          fp: false },
  { title: 'MFA Bypass Attempt',                  sev: 'critical', user: 'cfo@corp.com',   ip: '91.108.4.0',     detail: 'TOTP replay detected',            fp: false },
  { title: 'Password Reset — Suspicious',         sev: 'medium',   user: 'hr@corp.com',    ip: '198.51.100.23',  detail: 'Link clicked from different IP',  fp: true  },
  { title: 'Session Hijacking Attempt',           sev: 'high',     user: 'dev@corp.com',   ip: '103.21.244.0',   detail: 'Token reused after expiry',       fp: false },
  { title: 'OAuth Token Theft Attempt',           sev: 'high',     user: 'api-svc',        ip: '45.33.32.156',   detail: 'Redirect URI mismatch',           fp: false },
  { title: 'Credential Stuffing Attack',          sev: 'critical', user: 'multiple',       ip: '0.0.0.0/0',      detail: '1247 unique user attempts',       fp: false },
];

// ── AI Threat Explanations ────────────────────────────────────────────────
const aiExplanations = {
  'SQL Injection Attempt': 'This is a classic SQL injection attack where the attacker inserts malicious SQL code into an input field, hoping the server will execute it. The payload "OR 1=1" is designed to return all database records by making the WHERE clause always true. This could expose your entire user database. The attacking IP has been flagged in multiple threat intelligence databases as a known Tor exit node.',
  'Brute Force Attack — SSH': 'A systematic credential stuffing / brute force attack targeting your SSH service on port 22. The attacker is automating login attempts using a dictionary of common username/password combinations. With 47 attempts in under 2 minutes, this indicates automated tooling. Immediate action: implement fail2ban, restrict SSH to VPN only, disable password auth in favor of key-based.',
  'XSS Payload Detected': "Cross-Site Scripting attempt detected. The attacker is injecting a script tag into your search endpoint, hoping it will render in another user's browser and steal their session cookies. This could lead to account hijacking. The injected payload attempts to create an img tag with an onerror handler that sends cookies to an external server.",
  'Botnet C2 Callback': 'A device on your internal network (10.0.0.88) is attempting to communicate with a known Command & Control server at 51.15.62.101:4444. This strongly indicates a compromised internal host. The port 4444 is commonly used by Metasploit reverse shells. Isolate this device immediately and conduct forensic analysis.',
  'Privilege Escalation Attempt': 'An internal account (dev-account) with limited privileges is attempting to access the admin grants endpoint. This is consistent with a lateral movement attack where an attacker has compromised a low-privilege account and is trying to elevate access. Could indicate insider threat or a compromised developer workstation.',
  'DDoS Spike Detected': 'Volumetric Distributed Denial of Service attack detected. Traffic is originating from multiple geographically distributed IPs, indicating a coordinated botnet attack. The goal is to exhaust your server resources and make services unavailable to legitimate users. Activate your CDN DDoS mitigation and consider rate limiting at the edge.',
};

// ── Attack Timelines ──────────────────────────────────────────────────────
const attackTimelines = {
  'SQL Injection Attempt': [
    { t: 'Reconnaissance', d: 'Attacker probed common endpoints and identified injectable params' },
    { t: 'Payload Crafting', d: "SQLi payload constructed: ' OR 1=1 -- to bypass authentication" },
    { t: 'Attack Execution', d: 'Malicious request sent to /api/users?id= endpoint' },
    { t: 'WAF Intercept',    d: 'Web Application Firewall detected and blocked the request' },
    { t: 'Alert Generated',  d: 'SentinelAI raised CRITICAL alert and logged full payload' },
  ],
  'default': [
    { t: 'Initial Detection', d: 'Anomalous traffic pattern detected by SentinelAI ML model' },
    { t: 'Pattern Matching',  d: 'Signature matched against threat intelligence database' },
    { t: 'Risk Assessment',   d: 'Context analyzed: user history, geo, time, behavior baseline' },
    { t: 'Alert Raised',      d: 'Security team notified with full incident context' },
  ]
};

// ── Utility Helpers ───────────────────────────────────────────────────────
let eventId = 1000;
function genId()     { return 'EVT-' + (eventId++); }
function timeAgo(ms) {
  const s = Math.floor((Date.now() - ms) / 1000);
  if (s < 60)   return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  return Math.floor(s / 3600) + 'h ago';
}
function nowTime() {
  return new Date().toTimeString().slice(0, 8);
}
