const qs = (s) => document.querySelector(s);

async function fetchJson(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function renderStatus() {
  try {
    const status = await fetchJson('/api/status');
    qs('#statusJson').textContent = JSON.stringify(status, null, 2);
  } catch (e) {
    qs('#statusJson').textContent = 'Error loading status';
  }
}

async function renderAlerts() {
  try {
    const alerts = await fetchJson('/api/alerts?limit=50');
    const el = qs('#alertsList');
    el.innerHTML = '';
    if (!alerts.length) {
      el.innerHTML = '<li>No alerts</li>';
      return;
    }
    for (const a of alerts) {
      const li = document.createElement('li');
      li.innerHTML = `<strong>${a.timestamp || ''}</strong> — ${a.message || a.event_type || ''} <small>(${a.threat_score || ''})</small>`;
      el.appendChild(li);
    }
  } catch (e) {
    console.error('Alerts error', e);
    qs('#alertsList').innerHTML = `<li>Error loading alerts: ${e.message || e}</li>`;
  }
}

async function renderFL() {
  try {
    const rounds = await fetchJson('/api/fl_rounds');
    const el = qs('#flList');
    el.innerHTML = '';
    if (!rounds || rounds.length === 0) {
      el.innerHTML = '<li>No FL rounds</li>';
      return;
    }

    // Sort by timestamp (newest first) if available
    const sorted = rounds.slice().sort((a, b) => {
      const ta = a.timestamp || a.time || '';
      const tb = b.timestamp || b.time || '';
      if (!ta && !tb) return 0;
      return ta < tb ? 1 : ta > tb ? -1 : 0;
    });

    for (const r of sorted) {
      const roundNum = r.round ?? r.round_number ?? r.rounds ?? '?';
      const acc = r.accuracy ?? r.accuracy_percent ?? '?';
      const ts = r.timestamp || r.time || '';
      const li = document.createElement('li');
      li.textContent = `Round ${roundNum} — Accuracy: ${acc} — ${ts}`;
      el.appendChild(li);
    }
  } catch (e) {
    console.error('FL error', e);
    qs('#flList').innerHTML = `<li>Error loading FL rounds: ${e.message || e}</li>`;
  }
}

async function renderHoneypots() {
  try {
    const hp = await fetchJson('/api/honeypots');
    qs('#honeypotsJson').textContent = JSON.stringify(hp, null, 2);
  } catch (e) {
    qs('#honeypotsJson').textContent = 'No honeypot registry found';
  }
}

async function refreshAll() {
  await Promise.all([renderStatus(), renderAlerts(), renderFL(), renderHoneypots()]);
}

qs('#refresh').addEventListener('click', () => refreshAll());

let intervalId = null;
qs('#autoRefresh').addEventListener('change', (e) => {
  if (e.target.checked) {
    intervalId = setInterval(refreshAll, 5000);
  } else {
    clearInterval(intervalId);
    intervalId = null;
  }
});

// Boot
refreshAll();
