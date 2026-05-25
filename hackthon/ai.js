// ─────────────────────────────────────────────
// SAFE STATE INIT
// ─────────────────────────────────────────────
window.state = window.state || {};
state.aiMessages = state.aiMessages || [];

// ─────────────────────────────────────────────
// UTIL
// ─────────────────────────────────────────────
function escapeHtml(str = "") {
  return str.replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");
}

function random(items = []) {
  if (!items.length) return "";
  return items[Math.floor(Math.random() * items.length)];
}

// ─────────────────────────────────────────────
// UI HANDLER (FIXED IDS)
// ─────────────────────────────────────────────
function formatDisplayText(text = "") {
  return escapeHtml(text).replace(/\n/g, "<br>");
}

function appendMessage(role, text) {
  const chat = document.getElementById("chatBox"); // FIXED ID
  if (!chat) return;

  const div = document.createElement("div");
  div.className = `msg ${role}`;
  div.innerHTML = formatDisplayText(text);

  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}

// ─────────────────────────────────────────────
// TYPING EFFECT
// ─────────────────────────────────────────────
function showTyping() {
  const chat = document.getElementById("chatBox");
  const div = document.createElement("div");
  div.id = "typing";
  div.className = "msg";
  div.innerHTML = "<i>SentinelAI is analyzing...</i>";
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}

function removeTyping() {
  document.getElementById("typing")?.remove();
}

// ─────────────────────────────────────────────
// AI BRAIN (IMPROVED DYNAMIC RESPONSES)
// ─────────────────────────────────────────────
function sentinelBrain(msg) {
  const m = msg.toLowerCase();

  const responses = {
    greeting: [
      "System online.\nAll security modules are active.\nMonitoring queue is healthy.",
      "Hello.\nI am tracking traffic and anomalies in real time.\nYour environment is being reviewed continuously.",
      "AI SOC engine initialized successfully.\nThe monitoring layer is live.\nI am ready to assess your request."
    ],
    about: [
      "SentinelAI is a cybersecurity monitoring system.\nIt analyzes logs, detects malicious patterns, and suggests remediation steps.\nThink of it as a guided SOC assistant for real-time triage.",
      "SentinelAI focuses on threat detection and response.\nIt can help identify suspicious activity, assess risk, and recommend safe actions.\nIt is designed to support quick security decisions."
    ],
    sql: [
      "Critical: SQL Injection pattern detected in the database input layer.\nThis can expose records, bypass authentication, or corrupt application data.\nImmediate validation and parameterization should be applied.",
      "Attack vector identified: unsanitized SQL query execution.\nThe request appears to be manipulating the query string.\nUse prepared statements and strict input validation to contain it."
    ],
    phishing: [
      "High risk phishing attempt detected via suspicious domain or message content.\nThe communication may be attempting to steal credentials or trigger unsafe actions.\nBlock the source and warn the affected user immediately.",
      "Credential theft pattern identified in the message content.\nThis looks like a social engineering attempt aimed at harvesting access details.\nDisable links, verify the sender, and rotate credentials if needed."
    ],
    brute: [
      "Brute force activity detected on an authentication endpoint.\nRepeated failed sign-ins suggest credential stuffing or password guessing.\nApply rate limiting, lockouts, and MFA enforcement.",
      "Multiple failed login attempts indicate an active brute-force pattern.\nThe account surface is at elevated risk.\nReview access logs and require stronger authentication controls."
    ],
    malware: [
      "Malware indicators are present in the activity you described.\nThis may include suspicious payload execution, file tampering, or persistence behavior.\nIsolate the host and perform a forensic review before reconnecting it.",
      "Potential malware behavior detected.\nThe pattern suggests unauthorized execution or data manipulation.\nQuarantine the endpoint and check for persistence mechanisms."
    ],
    privacy: [
      "Privacy risk detected in the request.\nSensitive data exposure or insecure handling may be involved.\nLimit access, apply encryption, and review data retention policies.",
      "Data handling appears to be a privacy concern.\nProtecting stored or transmitted information should be a priority.\nUse minimization, masking, and secure access controls."
    ],
    network: [
      "Network-level risk is elevated.\nThe traffic pattern suggests abnormal connectivity or a possible scanning activity.\nInspect firewall logs, segment affected systems, and validate ingress rules.",
      "Abnormal network behavior is visible.\nThis may point to reconnaissance, tunneling, or an intrusion attempt.\nReview traffic flows and tighten perimeter monitoring."
    ],
    advice: [
      "A strong baseline for protection is to patch systems, enforce MFA, and review permissions.\nAlso limit exposure by disabling unused services and monitoring privileged activity.\nIf you want, I can turn this into a short incident checklist.",
      "For safer operations, keep backups current, verify software updates, and train users to spot social engineering.\nAdd monitoring around authentication, outbound traffic, and file changes.\nI can help you prioritize the highest-risk items first."
    ],
    default: [
      "No critical threat was confirmed from the input provided.\nThe request does not match a high-confidence indicator in the current rule set.\nI can help refine the query or investigate the next step.",
      "Input analyzed with low-to-moderate confidence.\nNo immediate incident pattern was identified from the text alone.\nIf you want, I can classify the scenario further or suggest preventive actions.",
      "This looks like a general inquiry rather than a direct threat signal.\nI have not found a strong malicious pattern in the wording.\nShare more context if you want a deeper assessment.",
      "The current message is not tied to a known attack pattern in the knowledge base.\nThat means the signal is either benign or needs more context.\nI can still help you with safe next steps and security guidance."
    ]
  };

  if (/\b(hi|hello|hey)\b/.test(m)) return random(responses.greeting);
  if (/(what is sentinelai|what is sentinel|tell me about sentinel|what does sentinelai do)/.test(m)) return random(responses.about);
  if (/(sql|database|injection|query)/.test(m)) return random(responses.sql);
  if (/(phishing|email|credential|password|bank|link|sender)/.test(m)) return random(responses.phishing);
  if (/(brute|login|authentication|credential stuffing|failed login)/.test(m)) return random(responses.brute);
  if (/(malware|virus|trojan|ransom|worm|payload|spyware)/.test(m)) return random(responses.malware);
  if (/(privacy|data leak|encrypt|backup|gdpr|compliance|confidential)/.test(m)) return random(responses.privacy);
  if (/(network|firewall|port|scan|vulnerability|exploit|ddos|recon|traffic)/.test(m)) return random(responses.network);
  if (/(protect|secure|how can i|best practice|recommend|safe|advice)/.test(m)) return random(responses.advice);

  return random(responses.default);
}

// ─────────────────────────────────────────────
// FIXED SEND FUNCTION (THIS IS THE MAIN FIX)
// ─────────────────────────────────────────────
function sendAI() {
  const input = document.getElementById("aiInput"); // ✅ FIXED
  const msg = input?.value?.trim();

  if (!msg) return;

  input.value = "";

  state.aiMessages.push({ role: "user", content: msg });
  appendMessage("user", msg);

  showTyping();

  setTimeout(() => {
    removeTyping();

    const reply = sentinelBrain(msg);

    state.aiMessages.push({ role: "assistant", content: reply });

    appendMessage("assistant", reply);
  }, 700);
}