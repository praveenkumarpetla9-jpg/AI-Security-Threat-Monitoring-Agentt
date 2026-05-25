// ── Charts ────────────────────────────────────────────────────────────────
let trendChart, catChart;

function initCharts() {
  // Trend Line Chart
  const trendCtx = document.getElementById('trendChart').getContext('2d');
  trendChart = new Chart(trendCtx, {
    type: 'line',
    data: {
      labels: Array.from({ length: 24 }, (_, i) => i + ':00'),
      datasets: [{
        label: 'Critical',
        data: state.trendData.slice(),
        borderColor: '#ef4444',
        backgroundColor: 'rgba(239,68,68,0.08)',
        fill: true,
        tension: 0.4,
        pointRadius: 2,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: {
          ticks: { color: '#475569', font: { size: 10 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 8 },
          grid:  { color: 'rgba(99,179,237,0.06)' }
        },
        y: {
          ticks: { color: '#475569', font: { size: 10 } },
          grid:  { color: 'rgba(99,179,237,0.06)' },
          beginAtZero: true
        }
      }
    }
  });

  // Category Doughnut Chart
  const catCtx = document.getElementById('catChart').getContext('2d');
  catChart = new Chart(catCtx, {
    type: 'doughnut',
    data: {
      labels: ['Injection', 'Credential', 'Malware', 'Recon', 'Exfil'],
      datasets: [{
        data: [35, 28, 18, 12, 7],
        backgroundColor: ['#ef4444', '#f97316', '#a855f7', '#eab308', '#14b8a6'],
        borderColor: '#0a0f1e',
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 11 }, boxWidth: 10 } }
      },
      cutout: '65%'
    }
  });
}

// ── Geo Renderer ──────────────────────────────────────────────────────────
function renderGeo() {
  const maxA = Math.max(...geoCountries.map(g => g.attacks));

  const fullHTML = geoCountries.map(g => `
    <div class="geo-item">
      <div class="geo-flag">${g.flag}</div>
      <div class="geo-info">
        <div class="geo-country">${g.name}</div>
        <div class="geo-ip">${g.ip}</div>
      </div>
      <div class="geo-bar-wrap">
        <div class="geo-bar-bg">
          <div class="geo-bar-fill" style="width:${Math.round(g.attacks / maxA * 100)}%"></div>
        </div>
      </div>
      <div class="geo-count">${g.attacks}</div>
    </div>`).join('');

  const miniHTML = geoCountries.slice(0, 4).map(g => `
    <div class="geo-item">
      <div class="geo-flag">${g.flag}</div>
      <div class="geo-info">
        <div class="geo-country">${g.name}</div>
        <div class="geo-ip">${g.ip}</div>
      </div>
      <div class="geo-count" style="color:var(--red);">${g.attacks}</div>
    </div>`).join('');

  document.getElementById('geo-mini').innerHTML = miniHTML;
  document.getElementById('geo-full').innerHTML = fullHTML;
}

// ── Monitoring Engine ─────────────────────────────────────────────────────
function startMonitoring() {
  let eventsThisMinute = 0;

  function spawnEvent() {
    if (Math.random() > 0.3) {
      const tmpl = threatTemplates[Math.floor(Math.random() * threatTemplates.length)];
      addThreat({ ...tmpl, id: genId(), ts: Date.now() });
    }
    if (Math.random() > 0.5) {
      const tmpl = logTemplates[Math.floor(Math.random() * logTemplates.length)];
      addLog(tmpl);
    }
    if (Math.random() > 0.6) {
      const tmpl = authTemplates[Math.floor(Math.random() * authTemplates.length)];
      addAuth({ ...tmpl, id: genId(), ts: Date.now() });
    }
    eventsThisMinute++;
  }

  // Spawn events every 2.8s
  setInterval(spawnEvent, 2800);

  // Update event rate counter every minute
  setInterval(() => {
    document.getElementById('event-counter').textContent = eventsThisMinute + ' events/min';
    eventsThisMinute = 0;
  }, 60000);

  // Update dashboard timestamp and metrics every 3s
  setInterval(() => {
    document.getElementById('last-updated').textContent =
      'Last updated: ' + new Date().toLocaleTimeString();
    updateMetricDisplays();
  }, 3000);

  // Seed with initial events on load
  for (let i = 0; i < 8; i++) setTimeout(spawnEvent, i * 300);
}

// ── Event Handlers ────────────────────────────────────────────────────────
function addThreat(threat) {
  state.threats.unshift(threat);
  if (state.threats.length > 200) state.threats.pop();

  if (!threat.fp) {
    if (threat.sev === 'critical') state.metrics.critical++;
    if (threat.sev === 'high')     state.metrics.high++;
    state.metrics.total++;
    state.trendData[new Date().getHours()]++;

    const h = new Date().getHours();
    if (trendChart) {
      trendChart.data.datasets[0].data[h] = state.trendData[h];
      trendChart.update('none');
    }

    if (threat.sev === 'critical') {
      state.alertCount++;
      document.getElementById('alert-count').textContent = state.alertCount;
      showNotif('🚨 Critical: ' + threat.title, threat.ip + ' · ' + threat.country);
    }
  } else {
    state.metrics.fp++;
  }

  renderThreatLists();
  updateBadges();
}

function addLog(log) {
  if (state.logPaused) return;
  state.logs.unshift({ ...log, ts: Date.now(), time: nowTime() });
  if (state.logs.length > 500) state.logs.pop();
  renderLogs();
  const cnt = document.getElementById('log-count');
  if (cnt) cnt.textContent = state.logs.length + ' events';
  document.getElementById('badge-logs').textContent = Math.min(state.logs.length, 99);
}

function addAuth(auth) {
  state.authEvents.unshift(auth);
  if (state.authEvents.length > 100) state.authEvents.pop();
  if (!auth.fp) {
    if (auth.sev === 'critical' || auth.sev === 'high') state.metrics.authFailed++;
    if (auth.title.includes('Suspicious') || auth.title.includes('Anomaly')) state.metrics.authSusp++;
  }
  state.metrics.authMfa += (Math.random() > 0.5) ? 1 : 0;
  renderAuthList();
  document.getElementById('badge-auth').textContent = Math.min(state.authEvents.length, 99);
}

// ── Metric & Badge Updates ────────────────────────────────────────────────
function updateMetricDisplays() {
  document.getElementById('m-critical').textContent    = state.metrics.critical;
  document.getElementById('m-high').textContent        = state.metrics.high;
  document.getElementById('m-fp').textContent          = state.metrics.fp;
  document.getElementById('m-total').textContent       = state.metrics.total;
  document.getElementById('auth-failed').textContent   = state.metrics.authFailed;
  document.getElementById('auth-suspicious').textContent = state.metrics.authSusp;
  document.getElementById('auth-mfa').textContent      = state.metrics.authMfa;
  document.getElementById('m-critical-d').textContent  = '↑ ' + Math.floor(state.metrics.critical * 0.3);
  document.getElementById('m-high-d').textContent      = '↑ ' + Math.floor(state.metrics.high * 0.2);
  document.getElementById('badge-critical').textContent = state.metrics.critical;
  document.getElementById('badge-threats').textContent  = Math.min(state.threats.filter(t => !t.fp).length, 99);
}

function updateBadges() {
  document.getElementById('badge-threats').textContent  = Math.min(state.threats.filter(t => !t.fp).length, 99);
  document.getElementById('badge-critical').textContent = state.metrics.critical;
}

// ── Threat List Renderers ─────────────────────────────────────────────────
function threatHTML(threats, limit) {
  return (limit ? state.threats.slice(0, limit) : state.threats)
    .filter(t => {
      if (limit) return !t.fp;
      const f = document.getElementById('threat-filter')?.value || 'all';
      return f === 'all' ? true : t.sev === f;
    })
    .map(t => `
      <div class="threat-item" onclick="openThreat('${t.id}')">
        <div class="sev-dot sev-${t.sev}"></div>
        <div class="threat-body">
          <div class="threat-title">${t.fp ? '<span style="opacity:0.4">[FILTERED] </span>' : ''}${t.title}</div>
          <div class="threat-meta">
            <span>${timeAgo(t.ts)}</span>
            <span>${t.ip}</span>
            <span>${t.country}</span>
            <span>${t.cat}</span>
            ${t.fp ? '<span style="color:var(--green)">FP · suppressed</span>' : ''}
          </div>
        </div>
        <div class="sev-tag tag-${t.sev}">${t.sev}</div>
      </div>`)
    .join('') || '<div class="empty-state">No events match the filter</div>';
}

function renderThreatLists() {
  const dash = document.getElementById('dash-threat-list');
  if (dash) dash.innerHTML = threatHTML(state.threats, 6);
  const full = document.getElementById('full-threat-list');
  if (full) full.innerHTML = threatHTML(state.threats, null);
}

function filterThreats() { renderThreatLists(); }
function clearThreats()  { state.threats = []; renderThreatLists(); }

// ── Log Renderer ──────────────────────────────────────────────────────────
function renderLogs() {
  const terminal = document.getElementById('log-terminal');
  if (!terminal) return;
  terminal.innerHTML = state.logs.slice(0, 80).map(l => `
    <div class="log-line">
      <span class="log-time">[${l.time}]</span>
      <span class="log-level-${l.level}">${l.level.toUpperCase().padEnd(4)}</span>
      <span class="log-msg">${l.msg}</span>
    </div>`).join('');
  terminal.scrollTop = 0;
}

function toggleLogPause() {
  state.logPaused = !state.logPaused;
  document.getElementById('log-pause-btn').textContent = state.logPaused ? '▶ Resume' : '⏸ Pause';
}

function clearLogs() { state.logs = []; renderLogs(); }

// ── Auth List Renderer ────────────────────────────────────────────────────
function renderAuthList() {
  const list = document.getElementById('auth-list');
  if (!list) return;
  list.innerHTML = state.authEvents.slice(0, 50).map(a => `
    <div class="threat-item">
      <div class="sev-dot sev-${a.sev}"></div>
      <div class="threat-body">
        <div class="threat-title">${a.title}</div>
        <div class="threat-meta">
          <span>${timeAgo(a.ts)}</span>
          <span>${a.user}</span>
          <span>${a.ip}</span>
          <span>${a.detail}</span>
        </div>
      </div>
      <div class="sev-tag tag-${a.sev}">${a.sev}</div>
    </div>`).join('')
    || '<div class="empty-state">Monitoring auth events...</div>';
}
