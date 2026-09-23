pub const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>randbotd — CA Command Center</title>
<style>
  :root {
    --bg: #090a10; --card: #121422; --card-border: #1e2238;
    --text: #e2e8f0; --text-muted: #94a3b8;
    --accent: #00ffcc; --accent-glow: rgba(0, 255, 204, 0.25);
    --purple: #8b5cf6; --red: #ff3366; --green: #10b981;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    padding: 24px; line-height: 1.5;
  }
  header {
    display: flex; justify-content: space-between; align-items: center;
    border-bottom: 1px solid var(--card-border); padding-bottom: 16px; margin-bottom: 24px;
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand h1 { font-size: 1.4rem; font-weight: 700; letter-spacing: -0.5px; }
  .badge {
    background: rgba(16, 185, 129, 0.15); color: var(--green);
    border: 1px solid rgba(16, 185, 129, 0.3); padding: 3px 10px; border-radius: 9999px;
    font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
  }
  .pubkey {
    font-family: monospace; font-size: 0.8rem; color: var(--text-muted);
    background: #0f111c; padding: 6px 12px; border-radius: 6px; border: 1px solid var(--card-border);
  }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card {
    background: var(--card); border: 1px solid var(--card-border);
    border-radius: 10px; padding: 20px; transition: transform 0.2s ease, border-color 0.2s ease;
  }
  .card:hover { transform: translateY(-2px); border-color: var(--accent); }
  .card h3 { font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px; }
  .card .stat { font-size: 2rem; font-weight: 800; color: var(--accent); margin-top: 8px; }
  .panels { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; margin-bottom: 24px; }
  @media (max-width: 900px) { .panels { grid-template-columns: 1fr; } }
  .panel {
    background: var(--card); border: 1px solid var(--card-border);
    border-radius: 10px; padding: 20px;
  }
  .panel h2 { font-size: 1.1rem; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }
  table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--card-border); }
  th { color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; }
  td.mono { font-family: monospace; font-size: 0.8rem; }
  .actions { display: flex; gap: 8px; }
  button {
    background: linear-gradient(135deg, var(--accent), #00bb99); color: #000;
    border: none; padding: 8px 14px; border-radius: 6px; font-weight: 700;
    font-size: 0.8rem; cursor: pointer; transition: opacity 0.2s ease;
  }
  button:hover { opacity: 0.9; }
  button.danger {
    background: linear-gradient(135deg, var(--red), #cc1144); color: #fff;
  }
  input, select {
    width: 100%; background: #0c0e18; border: 1px solid var(--card-border);
    color: var(--text); padding: 9px 12px; border-radius: 6px; margin-bottom: 12px; font-size: 0.85rem;
  }
  .chart-container {
    height: 180px; width: 100%; position: relative;
    background: #0c0e18; border-radius: 8px; padding: 12px; border: 1px solid var(--card-border);
  }
  svg { width: 100%; height: 100%; }
</style>
</head>
<body>
  <header>
    <div class="brand">
      <h1>randbotd Command Center</h1>
      <span class="badge" id="daemon-status">Online</span>
    </div>
    <div class="pubkey" id="node-pubkey">Node: Loading...</div>
  </header>

  <div class="grid">
    <div class="card"><h3>Certificate Authorities</h3><div class="stat" id="stat-cas">0</div></div>
    <div class="card"><h3>Active Offers</h3><div class="stat" id="stat-offers">0</div></div>
    <div class="card"><h3>Issued Certs</h3><div class="stat" id="stat-certs">0</div></div>
    <div class="card"><h3>Active CRLs</h3><div class="stat" id="stat-crls">0</div></div>
    <div class="card"><h3>Domain Purges</h3><div class="stat" id="stat-purges">0</div></div>
    <div class="card"><h3>P2P Peers</h3><div class="stat" id="stat-peers">0</div></div>
  </div>

  <div class="panels">
    <div class="panel">
      <h2>Registered CAs <button onclick="refreshData()">Refresh</button></h2>
      <table>
        <thead>
          <tr><th>CA ID</th><th>Common Name</th><th>Type</th><th>Status</th></tr>
        </thead>
        <tbody id="ca-table-body">
          <tr><td colspan="4" style="text-align: center; color: var(--text-muted);">Loading CAs...</td></tr>
        </tbody>
      </table>
    </div>

    <div class="panel">
      <h2>Certificate Revocation (CRL)</h2>
      <form id="revoke-form" onsubmit="submitRevoke(event)">
        <label style="font-size: 0.75rem; color: var(--text-muted);">TARGET CA ID (HEX)</label>
        <input id="rev-ca-id" placeholder="e.g. 7f8a... or select from table" required />
        <label style="font-size: 0.75rem; color: var(--text-muted);">CERTIFICATE SERIAL (HEX)</label>
        <input id="rev-serial" placeholder="e.g. 0102030405060708..." required />
        <label style="font-size: 0.75rem; color: var(--text-muted);">REVOCATION REASON</label>
        <select id="rev-reason">
          <option value="1">Key Compromise (1)</option>
          <option value="3">Affiliation Changed (3)</option>
          <option value="4">Superseded (4)</option>
          <option value="5">Cessation of Operation (5)</option>
          <option value="9">Privilege Withdrawn (9)</option>
        </select>
        <button type="submit" class="danger" style="width: 100%;">Issue CRL Revocation</button>
      </form>
    </div>
  </div>

  <div class="panels">
    <div class="panel">
      <h2>Swarm Bid Curve & Free-Market Dynamics (CA-05 / CA-06)</h2>
      <div class="chart-container">
        <svg viewBox="0 0 500 150" id="swarm-chart">
          <line x1="40" y1="130" x2="480" y2="130" stroke="#1e2238" stroke-width="2" />
          <line x1="40" y1="20" x2="40" y2="130" stroke="#1e2238" stroke-width="2" />
          <path d="M 40 120 Q 150 110, 250 70 T 480 30" fill="none" stroke="#00ffcc" stroke-width="3" />
          <circle cx="250" cy="70" r="5" fill="#8b5cf6" />
          <circle cx="360" cy="45" r="5" fill="#00ffcc" />
          <text x="50" y="25" fill="#94a3b8" font-size="11">Work Share %</text>
          <text x="400" y="145" fill="#94a3b8" font-size="11">Swarm Workers</text>
        </svg>
      </div>
      <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 10px;">
        Market Curve: Displays incumbent custodian revenue shares vs incoming under-bids for active CAs.
      </p>
    </div>

    <div class="panel">
      <h2>Bad-Domain Purge Engine (CA-07)</h2>
      <form id="purge-form" onsubmit="submitPurge(event)">
        <label style="font-size: 0.75rem; color: var(--text-muted);">TARGET CA ID (HEX)</label>
        <input id="purge-ca-id" placeholder="CA ID hex" required />
        <label style="font-size: 0.75rem; color: var(--text-muted);">OFFENDING DOMAIN</label>
        <input id="purge-domain" placeholder="malicious-domain.hns" required />
        <label style="font-size: 0.75rem; color: var(--text-muted);">REASON & DESCRIPTION</label>
        <input id="purge-desc" placeholder="Evidence of phishing / UTW strike" required />
        <button type="submit" class="danger" style="width: 100%;">Emit Domain Purge (Auto-Revoke Certs)</button>
      </form>
    </div>
  </div>

<script>
async function refreshData() {
  try {
    const sRes = await fetch('/api/status');
    const status = await sRes.json();
    document.getElementById('stat-cas').innerText = status.total_cas || 0;
    document.getElementById('stat-offers').innerText = status.total_offers || 0;
    document.getElementById('stat-certs').innerText = status.total_certs || 0;
    document.getElementById('stat-crls').innerText = status.total_crls || 0;
    document.getElementById('stat-purges').innerText = status.total_purges || 0;
    document.getElementById('stat-peers').innerText = status.peer_count || 0;
    document.getElementById('node-pubkey').innerText = 'Node: ' + (status.node_pubkey_hex ? status.node_pubkey_hex.substring(0, 16) + '...' : 'Unknown');

    const caRes = await fetch('/api/cas');
    const cas = await caRes.json();
    const tbody = document.getElementById('ca-table-body');
    if (cas.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No CAs registered.</td></tr>';
    } else {
      tbody.innerHTML = cas.map(ca => `
        <tr>
          <td class="mono" title="${ca.ca_id_hex}">${ca.ca_id_hex ? ca.ca_id_hex.substring(0, 16) + '...' : '-'}</td>
          <td><strong>${ca.subject ? ca.subject.common_name : '-'}</strong></td>
          <td>${ca.is_intermediate ? 'Intermediate' : 'Root CA'}</td>
          <td><span class="badge" style="background:${ca.is_draft ? 'rgba(255,165,0,0.15)' : 'rgba(16,185,129,0.15)'}; color:${ca.is_draft ? 'orange' : 'var(--green)'};">${ca.is_draft ? 'Draft' : 'Active'}</span></td>
        </tr>
      `).join('');
    }
  } catch (e) {
    console.error('Failed to refresh data', e);
  }
}

async function submitRevoke(e) {
  e.preventDefault();
  const ca_id_hex = document.getElementById('rev-ca-id').value.trim();
  const serial_hex = document.getElementById('rev-serial').value.trim();
  const reason = parseInt(document.getElementById('rev-reason').value, 10);
  try {
    const res = await fetch('/api/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ca_id_hex, serial_hex, reason })
    });
    const data = await res.json();
    alert(data.message || data.error || 'Revocation processed');
    refreshData();
  } catch (err) { alert('Revocation error: ' + err); }
}

async function submitPurge(e) {
  e.preventDefault();
  const ca_id_hex = document.getElementById('purge-ca-id').value.trim();
  const domain = document.getElementById('purge-domain').value.trim();
  const description = document.getElementById('purge-desc').value.trim();
  try {
    const res = await fetch('/api/purge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ca_id_hex, domain, description })
    });
    const data = await res.json();
    alert(data.message || data.error || 'Purge emitted');
    refreshData();
  } catch (err) { alert('Purge error: ' + err); }
}

window.onload = refreshData;
setInterval(refreshData, 5000);
</script>
</body>
</html>
"##;
