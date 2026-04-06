/* ===================================================
   ZERO-TRUST PRIVACY AUDITOR — app.js
   =================================================== */

'use strict';

// ---- State ----
let currentTab = 'trackers';

// ---- DOM refs ----
const auditForm     = document.getElementById('auditForm');
const urlInput      = document.getElementById('urlInput');
const auditBtn      = document.getElementById('auditBtn');
const loadingScreen = document.getElementById('loadingScreen');
const loadingUrl    = document.getElementById('loadingUrl');
const errorBanner   = document.getElementById('errorBanner');
const errorMessage  = document.getElementById('errorMessage');
const results       = document.getElementById('results');

// ---- Quick links ----
document.querySelectorAll('.quick-link').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    urlInput.value = link.dataset.url;
    runAudit();
  });
});

// ---- Form submit ----
auditForm.addEventListener('submit', e => {
  e.preventDefault();
  runAudit();
});

function runAudit() {
  const url = urlInput.value.trim();
  if (!url) { urlInput.focus(); return; }
  startLoading(url);
  fetchAudit(url);
}

// ---- Loading animation ----
const steps = ['step-ssl', 'step-headers', 'step-trackers', 'step-score'];
let stepIntervals = [];

function startLoading(url) {
  hideResults();
  hideError();
  loadingUrl.textContent = url;
  loadingScreen.hidden = false;
  auditBtn.disabled = true;

  // Reset steps
  steps.forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.className = 'step'; }
  });

  // Animate steps sequentially
  stepIntervals.forEach(clearTimeout);
  stepIntervals = [];
  steps.forEach((id, i) => {
    const t = setTimeout(() => {
      // Mark previous as done
      if (i > 0) {
        const prev = document.getElementById(steps[i - 1]);
        if (prev) prev.className = 'step done';
      }
      const el = document.getElementById(id);
      if (el) el.className = 'step active';
    }, i * 800);
    stepIntervals.push(t);
  });
}

function stopLoading() {
  loadingScreen.hidden = true;
  auditBtn.disabled = false;
  steps.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.className = 'step done';
  });
  stepIntervals.forEach(clearTimeout);
  stepIntervals = [];
}

// ---- Fetch ----
async function fetchAudit(url) {
  try {
    const res = await fetch('/api/audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    stopLoading();
    if (res.ok) {
      renderResults(data);
    } else {
      showError(data.error || 'Audit failed. Please try again.');
    }
  } catch (err) {
    stopLoading();
    showError('Could not reach the server. Make sure Flask is running.');
  }
}

// ---- Error ----
function showError(msg) {
  errorMessage.textContent = msg;
  errorBanner.hidden = false;
  results.hidden = true;
}
function hideError() { errorBanner.hidden = true; }
function hideResults() { results.hidden = true; }

// ---- Render all results ----
function renderResults(data) {
  // Header bar
  document.getElementById('resultsUrl').textContent = data.url || '—';
  const meta = [];
  if (data.status_code) meta.push(`HTTP ${data.status_code}`);
  if (data.elapsed_seconds) meta.push(`${data.elapsed_seconds}s`);
  if (data.fetch_error) meta.push(`⚠️ ${data.fetch_error.slice(0, 80)}`);
  document.getElementById('resultsMeta').textContent = meta.join('  ·  ');

  renderScore(data.score);
  renderSSL(data.ssl);
  renderClickjackMini(data.clickjacking);
  renderTrackerMini(data.trackers);
  renderHeaders(data.headers);
  renderTrackers(data.trackers);
  renderCookies(data.trackers);
  renderClickjackDetail(data.clickjacking);

  results.hidden = false;
  results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ---- Score gauge ----
function renderScore(score) {
  const CIRCUMFERENCE = 2 * Math.PI * 80; // 502.65
  const val = score.score || 0;
  const grade = score.grade || '?';
  const gradeColor = score.grade_color || '#38bdf8';

  const gaugeFill = document.getElementById('gaugeFill');
  const gaugeScore = document.getElementById('gaugeScore');
  const gaugeGrade = document.getElementById('gaugeGrade');

  gaugeFill.style.stroke = gradeColor;
  gaugeFill.style.filter = `drop-shadow(0 0 8px ${gradeColor})`;
  gaugeGrade.style.color = gradeColor;

  // Animate counter + gauge
  let current = 0;
  const duration = 1400;
  const frameTime = 16;
  const totalFrames = duration / frameTime;
  const increment = val / totalFrames;
  const offset = CIRCUMFERENCE - (val / 100) * CIRCUMFERENCE;

  // Trigger CSS transition for ring
  requestAnimationFrame(() => {
    gaugeFill.style.strokeDashoffset = offset;
  });

  const counter = setInterval(() => {
    current = Math.min(current + increment, val);
    gaugeScore.textContent = Math.round(current);
    if (current >= val) {
      clearInterval(counter);
      gaugeScore.textContent = val;
      gaugeGrade.textContent = grade;
    }
  }, frameTime);

  // Breakdown
  const breakdown = document.getElementById('scoreBreakdown');
  breakdown.innerHTML = (score.breakdown || []).map(b => {
    const pts = b.score;
    const isPenalty = pts < 0;
    return `
      <div class="breakdown-item">
        <span class="breakdown-cat">${b.category}</span>
        <span class="breakdown-pts ${isPenalty ? 'penalty' : 'positive'}">${pts > 0 ? '+' : ''}${pts}</span>
      </div>
    `;
  }).join('');
}

// ---- SSL mini card ----
function renderSSL(ssl) {
  const val = document.getElementById('sslValue');
  const sub = document.getElementById('sslSub');
  const badge = document.getElementById('sslBadge');

  if (ssl.uses_https && ssl.cert_valid) {
    val.textContent = 'HTTPS ✓';
    val.style.color = 'var(--green)';
    sub.textContent = `Issuer: ${ssl.cert_issuer} · Expires ${ssl.cert_expiry}`;
    const days = ssl.days_until_expiry;
    if (days !== null && days < 30) {
      setBadge(badge, `Expires in ${days}d`, 'yellow');
    } else {
      setBadge(badge, 'Secure', 'green');
    }
  } else if (ssl.uses_https && !ssl.cert_valid) {
    val.textContent = 'HTTPS (invalid cert)';
    val.style.color = 'var(--yellow)';
    sub.textContent = ssl.error || 'Certificate verification failed';
    setBadge(badge, 'Warning', 'yellow');
  } else {
    val.textContent = 'HTTP only';
    val.style.color = 'var(--red)';
    sub.textContent = 'No encryption — data transmitted in plain text';
    setBadge(badge, 'Insecure', 'red');
  }
}

// ---- Clickjacking mini ----
function renderClickjackMini(cj) {
  document.getElementById('clickjackValue').textContent = cj.label || '—';
  document.getElementById('clickjackSub').textContent =
    cj.status === 'SAFE' ? 'Site cannot be embedded in a frame' :
    cj.status === 'PARTIAL' ? 'Partial clickjacking protection' :
    'Site may be embeddable — clickjacking risk';
  setBadge(
    document.getElementById('clickjackBadge'),
    cj.label,
    cj.color === 'green' ? 'green' : cj.color === 'yellow' ? 'yellow' : 'red'
  );
}

// ---- Tracker mini ----
function renderTrackerMini(trackers) {
  const count = trackers.tracker_count || 0;
  const cookies = trackers.cookie_count || 0;
  document.getElementById('trackerMiniValue').textContent =
    `${count} tracker${count !== 1 ? 's' : ''} · ${cookies} cookie${cookies !== 1 ? 's' : ''}`;
  document.getElementById('trackerMiniSub').textContent =
    count === 0 ? 'No known trackers detected on this page' :
    count <= 3 ? 'Low number of trackers' :
    count <= 7 ? 'Moderate tracking activity' : 'Heavy tracking activity';
  setBadge(
    document.getElementById('trackerMiniBadge'),
    count === 0 ? 'Clean' : count <= 3 ? 'Low' : count <= 7 ? 'Moderate' : 'Heavy',
    count === 0 ? 'green' : count <= 3 ? 'yellow' : 'red'
  );
}

// ---- Security Headers ----
function renderHeaders(headers) {
  const score = headers.score || 0;
  const max = headers.max_score || 80;
  document.getElementById('headerScore').textContent = `${score} / ${max} pts`;

  const list = document.getElementById('headerList');
  list.innerHTML = Object.entries(headers.headers || {}).map(([name, info]) => {
    const cls = info.present ? 'badge badge-green' : 'badge badge-red';
    const statusText = info.present ? '✓ Present' : '✗ Missing';
    const valueHtml = info.present && info.value
      ? `<div class="header-value">${truncate(info.value, 80)}</div>` : '';
    const sevColor = info.severity === 'critical' ? 'var(--red)' :
                     info.severity === 'high' ? 'var(--orange)' : 'var(--yellow)';
    return `
      <div class="header-item">
        <div>
          <div class="header-name">${name}</div>
          <div class="header-desc">${info.description}</div>
          ${valueHtml}
        </div>
        <div class="header-right">
          <span class="${cls}">${statusText}</span>
          <span class="header-pts" style="color:${info.present ? 'var(--green)' : sevColor}">
            ${info.present ? `+${info.points}` : `−${info.points}`} pts
          </span>
        </div>
      </div>
    `;
  }).join('');
}

// ---- Tracker list ----
function renderTrackers(trackers) {
  const list = document.getElementById('trackerList');
  const items = trackers.trackers || [];

  // Badge counts
  document.getElementById('tcCounts').innerHTML = `
    <span class="badge badge-red">${items.length} tracker${items.length !== 1 ? 's' : ''}</span>
    <span class="badge badge-cyan">${trackers.cookie_count || 0} cookie${trackers.cookie_count !== 1 ? 's' : ''}</span>
  `;

  if (items.length === 0) {
    list.innerHTML = `<div class="no-trackers">✅ No known trackers detected!</div>`;
    return;
  }

  list.innerHTML = items.map(t => `
    <div class="tracker-item">
      <div>
        <div class="tracker-domain">${t.domain}</div>
        <div class="tracker-cat">${t.category} · Found in: ${[...new Set(t.found_in)].join(', ')}</div>
      </div>
      <span class="badge badge-red">Tracker</span>
    </div>
  `).join('');
}

// ---- Cookie list ----
function renderCookies(trackers) {
  const list = document.getElementById('cookieList');
  const cookies = trackers.cookies || [];

  if (cookies.length === 0) {
    list.innerHTML = `<div class="no-trackers" style="color:var(--text-muted)">No Set-Cookie headers detected.</div>`;
    return;
  }

  list.innerHTML = cookies.map(c => `
    <div class="cookie-item">
      <div class="cookie-name">${c.name}</div>
      <div class="cookie-flags">
        <span class="cookie-flag ${c.secure ? 'flag-ok' : 'flag-warn'}">${c.secure ? '🔒 Secure' : '⚠️ No Secure'}</span>
        <span class="cookie-flag ${c.httponly ? 'flag-ok' : 'flag-warn'}">${c.httponly ? '🛡 HttpOnly' : '⚠️ No HttpOnly'}</span>
        <span class="cookie-flag ${c.samesite !== 'Not set' ? 'flag-ok' : 'flag-neutral'}">SameSite: ${c.samesite}</span>
      </div>
    </div>
  `).join('');
}

// ---- Clickjacking detail ----
function renderClickjackDetail(cj) {
  setBadge(
    document.getElementById('clickjackDetailBadge'),
    cj.label,
    cj.color === 'green' ? 'green' : cj.color === 'yellow' ? 'yellow' : 'red'
  );

  const container = document.getElementById('clickjackDetails');
  container.innerHTML = (cj.details || []).map(d =>
    `<div class="cj-item">${d}</div>`
  ).join('');
}

// ---- Tab switcher ----
function switchTab(tab) {
  currentTab = tab;
  document.getElementById('tabTrackers').classList.toggle('active', tab === 'trackers');
  document.getElementById('tabCookies').classList.toggle('active', tab === 'cookies');
  document.getElementById('panelTrackers').hidden = tab !== 'trackers';
  document.getElementById('panelCookies').hidden = tab !== 'cookies';
}
window.switchTab = switchTab;

// ---- Helpers ----
function setBadge(el, text, color) {
  el.className = `badge badge-${color}`;
  el.textContent = text;
}

function truncate(str, n) {
  return str.length > n ? str.slice(0, n) + '…' : str;
}
