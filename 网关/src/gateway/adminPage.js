export function adminPage() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>sub-gateway analyst</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f4f6f8;
      --panel: #ffffff;
      --panel-2: #f9fafb;
      --text: #17202a;
      --muted: #64748b;
      --line: #d7dde6;
      --accent: #1769e0;
      --accent-2: #00a389;
      --warn: #b7791f;
      --danger: #c2410c;
      --soft: #eef4ff;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    header {
      position: sticky;
      top: 0;
      z-index: 5;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 12px 18px;
      border-bottom: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.96);
      backdrop-filter: blur(8px);
    }
    h1 { margin: 0; font-size: 18px; }
    h2 { margin: 0 0 12px; font-size: 15px; }
    h3 { margin: 0; font-size: 13px; }
    main {
      display: grid;
      grid-template-columns: 240px minmax(0, 1fr);
      min-height: calc(100vh - 61px);
    }
    nav {
      padding: 14px;
      border-right: 1px solid var(--line);
      background: #fbfcfe;
    }
    .navbtn {
      width: 100%;
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 8px;
      border: 1px solid transparent;
      background: transparent;
      color: var(--text);
      text-align: left;
    }
    .navbtn.active {
      border-color: #bdd2f6;
      background: var(--soft);
      color: #0f4da3;
    }
    .page { display: none; padding: 16px; }
    .page.active { display: block; }
    .toolbar {
      display: flex;
      align-items: end;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 14px;
    }
    .toolbar > div { min-width: 150px; }
    label {
      display: block;
      margin: 0 0 5px;
      color: var(--muted);
      font-size: 12px;
    }
    input, textarea, select {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 9px;
      background: #fff;
      color: var(--text);
      font: inherit;
    }
    textarea { min-height: 72px; resize: vertical; }
    button {
      border: 1px solid var(--accent);
      border-radius: 6px;
      background: var(--accent);
      color: #fff;
      padding: 8px 10px;
      font: inherit;
      cursor: pointer;
      white-space: nowrap;
    }
    button.secondary { background: #fff; color: var(--accent); }
    button.danger { border-color: var(--danger); background: var(--danger); }
    button.ghost { border-color: var(--line); background: #fff; color: var(--text); }
    .grid { display: grid; gap: 14px; }
    .cols-2 { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }
    .cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .panel {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      padding: 14px;
      min-width: 0;
    }
    .metric {
      display: grid;
      gap: 4px;
      min-height: 86px;
    }
    .metric strong { font-size: 28px; line-height: 1; }
    .metric span { color: var(--muted); font-size: 12px; }
    .row { display: flex; gap: 8px; align-items: end; flex-wrap: wrap; }
    .row > * { flex: 1; min-width: 120px; }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .status {
      color: var(--muted);
      font-size: 12px;
      min-height: 18px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }
    th, td {
      text-align: left;
      padding: 7px 8px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }
    th { color: var(--muted); font-weight: 600; background: var(--panel-2); }
    td.truncate {
      max-width: 280px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .tablewrap {
      max-height: 560px;
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    .pill {
      display: inline-block;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 2px 7px;
      color: var(--muted);
      font-size: 12px;
      background: #fff;
    }
    .bar {
      height: 28px;
      display: flex;
      align-items: center;
      gap: 8px;
      margin: 8px 0;
    }
    .barlabel { width: 42px; color: var(--muted); font-size: 12px; }
    .barfill {
      height: 12px;
      min-width: 4px;
      border-radius: 999px;
      background: var(--accent);
    }
    .graph {
      width: 100%;
      height: 520px;
      min-height: 360px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfdff;
      overflow: hidden;
    }
    .filters {
      display: grid;
      gap: 8px;
    }
    .filter-row {
      display: grid;
      grid-template-columns: 170px 140px minmax(180px, 1fr) 40px;
      gap: 8px;
      align-items: end;
    }
    pre {
      margin: 0;
      padding: 12px;
      max-height: 420px;
      overflow: auto;
      border-radius: 8px;
      background: #111827;
      color: #e5edf8;
      font-size: 12px;
      white-space: pre-wrap;
      word-break: break-word;
    }
    @media (max-width: 980px) {
      main { grid-template-columns: 1fr; }
      nav { border-right: 0; border-bottom: 1px solid var(--line); }
      .cols-2, .cols-3 { grid-template-columns: 1fr; }
      .filter-row { grid-template-columns: 1fr; }
      header { align-items: flex-start; flex-direction: column; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>sub-gateway analyst</h1>
      <div id="status" class="status"></div>
    </div>
    <div class="toolbar" style="margin:0;">
      <div style="min-width:260px;">
        <label for="token">Admin token</label>
        <input id="token" type="password" autocomplete="off" placeholder="Bearer token">
      </div>
      <button id="saveToken" type="button">Save</button>
      <button id="health" class="secondary" type="button">Health</button>
    </div>
  </header>
  <main>
    <nav>
      <button class="navbtn active" data-page="dashboard" type="button">Dashboard <span>01</span></button>
      <button class="navbtn" data-page="investigate" type="button">Investigate <span>02</span></button>
      <button class="navbtn" data-page="query" type="button">Event Query <span>03</span></button>
      <button class="navbtn" data-page="registry" type="button">IP Registry <span>04</span></button>
      <button class="navbtn" data-page="raw" type="button">Raw Result <span>05</span></button>
    </nav>
    <section id="dashboard" class="page active">
      <div class="toolbar">
        <div>
          <label for="dashDays">Days</label>
          <input id="dashDays" type="number" min="1" max="365" value="7">
        </div>
        <div>
          <label for="dashLimit">Limit</label>
          <input id="dashLimit" type="number" min="1" max="10000" value="200">
        </div>
        <button id="loadDashboard" type="button">Refresh</button>
      </div>
      <div class="grid cols-3">
        <div class="panel metric"><span>Level 1 seeds</span><strong id="mL1">0</strong><span>Direct suspicious IPs</span></div>
        <div class="panel metric"><span>Level 2 related</span><strong id="mL2">0</strong><span>Shared token IPs</span></div>
        <div class="panel metric"><span>Level 3 strong</span><strong id="mL3">0</strong><span>Multiple overlaps</span></div>
      </div>
      <div class="grid cols-2" style="margin-top:14px;">
        <div class="panel">
          <h2>Risk Levels</h2>
          <div id="riskBars"></div>
        </div>
        <div class="panel">
          <h2>Top Seeds</h2>
          <div id="seedTable" class="tablewrap"></div>
        </div>
      </div>
    </section>

    <section id="investigate" class="page">
      <div class="toolbar">
        <div>
          <label for="lookupIp">IP</label>
          <input id="lookupIp" placeholder="47.243.132.26">
        </div>
        <div>
          <label for="lookupToken">Token or token_hash</label>
          <input id="lookupToken" placeholder="raw token or sha256 hash">
        </div>
        <div>
          <label for="days">Days</label>
          <input id="days" type="number" min="1" max="365" value="30">
        </div>
        <div>
          <label for="limit">Limit</label>
          <input id="limit" type="number" min="1" max="10000" value="1000">
        </div>
      </div>
      <div class="actions" style="margin-bottom:14px;">
        <button id="riskIp" type="button">Risk IP</button>
        <button id="ipTokenGraph" class="secondary" type="button">Graph</button>
        <button id="ipRecords" class="secondary" type="button">IP Records</button>
        <button id="tokenProfile" class="secondary" type="button">Token IPs</button>
      </div>
      <div class="grid cols-2">
        <div class="panel">
          <h2>IP Token Graph</h2>
          <div id="graph" class="graph"></div>
        </div>
        <div class="panel">
          <h2>Investigation Table</h2>
          <div id="investigationTable" class="tablewrap"></div>
        </div>
      </div>
    </section>

    <section id="query" class="page">
      <div class="toolbar">
        <div>
          <label for="queryDays">Days</label>
          <input id="queryDays" type="number" min="1" max="365" value="7">
        </div>
        <div>
          <label for="queryLimit">Limit</label>
          <input id="queryLimit" type="number" min="1" max="10000" value="200">
        </div>
        <button id="addFilter" class="secondary" type="button">Add Filter</button>
        <button id="runQuery" type="button">Run Query</button>
      </div>
      <div class="panel" style="margin-bottom:14px;">
        <h2>Filters</h2>
        <div id="filters" class="filters"></div>
      </div>
      <div class="panel">
        <h2>Events</h2>
        <div id="queryTable" class="tablewrap"></div>
      </div>
    </section>

    <section id="registry" class="page">
      <div class="grid cols-2">
        <div class="panel">
          <h2>Manual Suspicious IP</h2>
          <label for="ipOrCidr">IP or CIDR</label>
          <input id="ipOrCidr" placeholder="8.8.8.8 or 8.8.8.0/24">
          <label for="reason">Reason</label>
          <input id="reason" value="manual_suspicious">
          <label for="note">Note</label>
          <textarea id="note" placeholder="optional"></textarea>
          <div class="actions" style="margin-top:12px;">
            <button id="addSuspicious" type="button">Add</button>
            <button id="deleteSuspicious" class="danger" type="button">Delete</button>
            <button id="listSuspicious" class="secondary" type="button">List</button>
          </div>
        </div>
        <div class="panel">
          <h2>Registry</h2>
          <div id="registryTable" class="tablewrap"></div>
        </div>
      </div>
    </section>

    <section id="raw" class="page">
      <div class="toolbar">
        <button id="clear" class="secondary" type="button">Clear</button>
      </div>
      <pre id="output">{}</pre>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const status = $('status');
    const output = $('output');
    const fields = ['tenant_id', 'host', 'origin_base_url', 'token_raw', 'token_hash', 'client_ip', 'decision', 'risk_reason', 'flag', 'client_type', 'user_agent'];
    const ops = [
      ['eq', '='],
      ['ne', '!='],
      ['contains', 'contains'],
      ['not_contains', 'not contains'],
      ['starts_with', 'starts with'],
      ['empty', 'empty'],
      ['not_empty', 'not empty']
    ];
    $('token').value = sessionStorage.getItem('subgw_admin_token') || '';

    function token() { return $('token').value.trim(); }
    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
    }
    function qs(params) {
      const out = new URLSearchParams();
      for (const [key, value] of Object.entries(params)) {
        if (value != null && value !== '') out.set(key, value);
      }
      return out.toString();
    }
    async function api(path, options = {}) {
      status.textContent = 'Loading...';
      const headers = { ...(options.headers || {}) };
      if (token()) headers.authorization = 'Bearer ' + token();
      if (options.body && !headers['content-type']) headers['content-type'] = 'application/json';
      const res = await fetch(path, { ...options, headers });
      const text = await res.text();
      let data;
      try { data = JSON.parse(text); } catch { data = { ok: res.ok, raw: text }; }
      output.textContent = JSON.stringify(data, null, 2);
      status.textContent = res.ok ? 'OK' : 'Error ' + res.status;
      if (!res.ok) throw new Error(data.error || text || 'request failed');
      return data;
    }
    function setPage(id) {
      document.querySelectorAll('.page').forEach((el) => el.classList.toggle('active', el.id === id));
      document.querySelectorAll('.navbtn').forEach((el) => el.classList.toggle('active', el.dataset.page === id));
    }
    document.querySelectorAll('.navbtn').forEach((btn) => btn.onclick = () => setPage(btn.dataset.page));

    function table(rows, columns) {
      if (!rows || rows.length === 0) return '<div class="status" style="padding:12px;">No data</div>';
      const head = '<thead><tr>' + columns.map((c) => '<th>' + escapeHtml(c.label) + '</th>').join('') + '</tr></thead>';
      const body = '<tbody>' + rows.map((row) => '<tr>' + columns.map((c) => {
        const value = c.render ? c.render(row) : row[c.key];
        return '<td class="' + (c.truncate ? 'truncate' : '') + '">' + escapeHtml(value) + '</td>';
      }).join('') + '</tr>').join('') + '</tbody>';
      return '<table>' + head + body + '</table>';
    }
    function recordColumns() {
      return [
        { key: 'ts', label: 'time' },
        { key: 'tenant_id', label: 'tenant' },
        { key: 'host', label: 'host' },
        { key: 'token_raw', label: 'token', truncate: true },
        { key: 'client_ip', label: 'ip' },
        { key: 'decision', label: 'decision' },
        { key: 'risk_reason', label: 'reason' },
        { key: 'user_agent', label: 'ua', truncate: true }
      ];
    }
    function renderBars(summary) {
      const counts = [
        ['L1', summary.level1?.length || 0, '#1769e0'],
        ['L2', summary.level2?.length || 0, '#00a389'],
        ['L3', summary.level3?.length || 0, '#c2410c']
      ];
      const max = Math.max(1, ...counts.map((item) => item[1]));
      $('riskBars').innerHTML = counts.map((item) => {
        const width = Math.max(4, Math.round(item[1] / max * 100));
        return '<div class="bar"><div class="barlabel">' + item[0] + '</div><div class="barfill" style="width:' + width + '%;background:' + item[2] + ';"></div><span class="pill">' + item[1] + '</span></div>';
      }).join('');
    }
    function loadCytoscape() {
      if (window.cytoscape) return Promise.resolve(window.cytoscape);
      if (window.__cytoscapeLoading) return window.__cytoscapeLoading;
      window.__cytoscapeLoading = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/cytoscape@3.30.2/dist/cytoscape.min.js';
        script.async = true;
        script.onload = () => resolve(window.cytoscape);
        script.onerror = () => reject(new Error('Cytoscape load failed'));
        document.head.appendChild(script);
      });
      return window.__cytoscapeLoading;
    }
    function graphElements(data) {
      const tokens = (data.tokens || []).slice(0, 40);
      const seed = data.ip || $('lookupIp').value.trim() || 'seed';
      const elements = [
        { data: { id: 'seed:' + seed, label: seed, kind: 'seed', raw: seed } }
      ];
      const seenIps = new Set();
      for (const t of tokens) {
        const tokenId = 'token:' + t.token_hash;
        const tokenLabel = (t.token_raw || t.token_hash || '').slice(0, 18) || 'token';
        elements.push({ data: { id: tokenId, label: tokenLabel, kind: 'token', raw: t.token_raw || t.token_hash } });
        elements.push({ data: { id: 'edge:seed:' + t.token_hash, source: 'seed:' + seed, target: tokenId, weight: Number(t.seed_hits || 1) } });
        for (const ip of (t.other_ips || []).slice(0, 60)) {
          const ipId = 'ip:' + ip;
          if (!seenIps.has(ip)) {
            seenIps.add(ip);
            elements.push({ data: { id: ipId, label: ip, kind: 'ip', raw: ip } });
          }
          elements.push({ data: { id: 'edge:' + t.token_hash + ':' + ip, source: tokenId, target: ipId, weight: 1 } });
        }
      }
      return elements;
    }
    function renderSvgGraph(data) {
      const tokens = data.tokens || [];
      const seed = data.ip || $('lookupIp').value.trim() || 'seed';
      const tokenNodes = tokens.slice(0, 8);
      const otherIps = [...new Set(tokenNodes.flatMap((t) => t.other_ips || []))].slice(0, 18);
      const width = 860;
      const height = Math.max(360, Math.max(tokenNodes.length, otherIps.length, 1) * 46 + 60);
      const seedY = Math.round(height / 2);
      const tokenStep = height / Math.max(tokenNodes.length + 1, 2);
      const ipStep = height / Math.max(otherIps.length + 1, 2);
      const tokenPos = new Map(tokenNodes.map((t, i) => [t.token_hash, { x: 390, y: Math.round((i + 1) * tokenStep) }]));
      const ipPos = new Map(otherIps.map((ip, i) => [ip, { x: 700, y: Math.round((i + 1) * ipStep) }]));
      let svg = '<svg viewBox="0 0 ' + width + ' ' + height + '" width="100%" height="' + height + '" role="img">';
      svg += '<rect width="' + width + '" height="' + height + '" fill="#fbfdff"/>';
      for (const t of tokenNodes) {
        const tp = tokenPos.get(t.token_hash);
        svg += '<line x1="150" y1="' + seedY + '" x2="' + tp.x + '" y2="' + tp.y + '" stroke="#9bb7dd" stroke-width="1.5"/>';
        for (const ip of (t.other_ips || []).slice(0, 18)) {
          const ipP = ipPos.get(ip);
          if (ipP) svg += '<line x1="' + tp.x + '" y1="' + tp.y + '" x2="' + ipP.x + '" y2="' + ipP.y + '" stroke="#b7c6d8" stroke-width="1"/>';
        }
      }
      svg += '<circle cx="150" cy="' + seedY + '" r="28" fill="#1769e0"/><text x="150" y="' + (seedY + 4) + '" text-anchor="middle" fill="#fff" font-size="11">seed</text>';
      svg += '<text x="150" y="' + (seedY + 48) + '" text-anchor="middle" fill="#17202a" font-size="12">' + escapeHtml(seed) + '</text>';
      for (const t of tokenNodes) {
        const p = tokenPos.get(t.token_hash);
        svg += '<circle cx="' + p.x + '" cy="' + p.y + '" r="22" fill="#00a389"/>';
        svg += '<text x="' + p.x + '" y="' + (p.y + 4) + '" text-anchor="middle" fill="#fff" font-size="10">token</text>';
        svg += '<text x="' + p.x + '" y="' + (p.y + 38) + '" text-anchor="middle" fill="#17202a" font-size="11">' + escapeHtml(String(t.token_hash || '').slice(0, 10)) + '</text>';
      }
      for (const ip of otherIps) {
        const p = ipPos.get(ip);
        svg += '<circle cx="' + p.x + '" cy="' + p.y + '" r="18" fill="#f59e0b"/>';
        svg += '<text x="' + (p.x + 26) + '" y="' + (p.y + 4) + '" fill="#17202a" font-size="11">' + escapeHtml(ip) + '</text>';
      }
      svg += '</svg>';
      $('graph').innerHTML = svg;
    }
    async function renderGraph(data) {
      try {
        const cytoscape = await loadCytoscape();
        const container = $('graph');
        container.innerHTML = '';
        const cy = cytoscape({
          container,
          elements: graphElements(data),
          wheelSensitivity: 0.18,
          style: [
            {
              selector: 'node',
              style: {
                'label': 'data(label)',
                'font-size': 11,
                'text-valign': 'bottom',
                'text-halign': 'center',
                'text-margin-y': 8,
                'color': '#17202a',
                'background-color': '#64748b',
                'width': 34,
                'height': 34,
                'border-width': 2,
                'border-color': '#ffffff'
              }
            },
            { selector: 'node[kind = "seed"]', style: { 'background-color': '#1769e0', 'width': 54, 'height': 54, 'color': '#0f305f', 'font-weight': 700 } },
            { selector: 'node[kind = "token"]', style: { 'background-color': '#00a389', 'shape': 'round-rectangle', 'width': 48, 'height': 34 } },
            { selector: 'node[kind = "ip"]', style: { 'background-color': '#f59e0b' } },
            {
              selector: 'edge',
              style: {
                'width': 1.5,
                'line-color': '#b7c6d8',
                'target-arrow-color': '#b7c6d8',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier'
              }
            },
            { selector: ':selected', style: { 'border-color': '#c2410c', 'border-width': 4, 'line-color': '#c2410c', 'target-arrow-color': '#c2410c' } }
          ],
          layout: {
            name: 'breadthfirst',
            directed: true,
            padding: 35,
            spacingFactor: 1.25,
            roots: ['seed:' + (data.ip || $('lookupIp').value.trim() || 'seed')]
          }
        });
        window.__subgwCy = cy;
        cy.on('tap', 'node', (evt) => {
          const node = evt.target;
          const kind = node.data('kind');
          const raw = node.data('raw') || '';
          if (kind === 'ip' || kind === 'seed') $('lookupIp').value = raw;
          if (kind === 'token') $('lookupToken').value = raw;
          status.textContent = kind + ': ' + raw;
        });
        setTimeout(() => cy.fit(undefined, 30), 80);
      } catch (err) {
        status.textContent = err.message + ', using SVG fallback';
        renderSvgGraph(data);
      }
    }
    async function loadDashboard() {
      const data = await api('/-/analytics/risk-summary?' + qs({ days: $('dashDays').value, limit: $('dashLimit').value }));
      $('mL1').textContent = data.level1?.length || 0;
      $('mL2').textContent = data.level2?.length || 0;
      $('mL3').textContent = data.level3?.length || 0;
      renderBars(data);
      $('seedTable').innerHTML = table(data.level1 || [], [
        { key: 'client_ip', label: 'ip' },
        { key: 'tenant_count', label: 'tenants' },
        { key: 'token_count', label: 'tokens' },
        { key: 'hits', label: 'hits' },
        { key: 'reasons', label: 'reasons', render: (r) => (r.reasons || []).join(',') }
      ]);
    }
    function addFilterRow(values = {}) {
      const row = document.createElement('div');
      row.className = 'filter-row';
      row.innerHTML =
        '<div><label>Field</label><select class="filter-field">' + fields.map((f) => '<option value="' + f + '">' + f + '</option>').join('') + '</select></div>' +
        '<div><label>Operator</label><select class="filter-op">' + ops.map((op) => '<option value="' + op[0] + '">' + op[1] + '</option>').join('') + '</select></div>' +
        '<div><label>Value</label><input class="filter-value" placeholder="value"></div>' +
        '<button class="ghost remove-filter" type="button">x</button>';
      row.querySelector('.filter-field').value = values.field || 'client_ip';
      row.querySelector('.filter-op').value = values.op || 'eq';
      row.querySelector('.filter-value').value = values.value || '';
      row.querySelector('.remove-filter').onclick = () => row.remove();
      $('filters').appendChild(row);
    }
    function collectFilters() {
      return [...document.querySelectorAll('.filter-row')].map((row) => ({
        field: row.querySelector('.filter-field').value,
        op: row.querySelector('.filter-op').value,
        value: row.querySelector('.filter-value').value
      }));
    }
    async function runQuery() {
      const data = await api('/-/analytics/events?' + qs({
        days: $('queryDays').value,
        limit: $('queryLimit').value,
        filters: JSON.stringify(collectFilters())
      }));
      $('queryTable').innerHTML = table(data.records || [], recordColumns());
    }
    $('saveToken').onclick = () => { sessionStorage.setItem('subgw_admin_token', token()); status.textContent = 'Token saved'; };
    $('health').onclick = () => api('/-/health');
    $('clear').onclick = () => { output.textContent = '{}'; status.textContent = ''; };
    $('loadDashboard').onclick = loadDashboard;
    $('riskIp').onclick = async () => {
      const data = await api('/-/analytics/risk-ip?' + qs({ ip: $('lookupIp').value.trim(), days: $('days').value, limit: $('limit').value }));
      $('investigationTable').innerHTML = table([data.profile], [
        { key: 'client_ip', label: 'ip' },
        { key: 'tenant_count', label: 'tenants' },
        { key: 'token_count', label: 'tokens' },
        { key: 'hits', label: 'hits' },
        { key: 'risk_level', label: 'level' },
        { key: 'reasons', label: 'reasons', render: (r) => (r.reasons || []).join(',') }
      ]);
    };
    $('ipTokenGraph').onclick = async () => {
      const data = await api('/-/analytics/ip-token-graph?' + qs({ ip: $('lookupIp').value.trim(), days: $('days').value, limit: $('limit').value }));
      await renderGraph(data);
      $('investigationTable').innerHTML = table(data.tokens || [], [
        { key: 'token_hash', label: 'token_hash', truncate: true },
        { key: 'token_raw', label: 'token', truncate: true },
        { key: 'seed_hits', label: 'seed hits' },
        { key: 'ip_count', label: 'ips' },
        { key: 'other_ips', label: 'other ips', render: (r) => (r.other_ips || []).join(', ') }
      ]);
    };
    $('ipRecords').onclick = async () => {
      const data = await api('/-/analytics/ip-access-records?' + qs({ ip: $('lookupIp').value.trim(), days: $('days').value, limit: $('limit').value }));
      $('investigationTable').innerHTML = table(data.records || [], recordColumns());
    };
    $('tokenProfile').onclick = async () => {
      const value = $('lookupToken').value.trim();
      const key = /^[a-fA-F0-9]{64}$/.test(value) ? 'token_hash' : 'token';
      const data = await api('/-/analytics/token?' + qs({ [key]: value, limit: $('limit').value }));
      $('investigationTable').innerHTML = table(data.ips || [], [
        { key: 'tenant_id', label: 'tenant' },
        { key: 'client_ip', label: 'ip' },
        { key: 'hits', label: 'hits' },
        { key: 'suspicious_hits', label: 'risk hits' },
        { key: 'first_seen', label: 'first' },
        { key: 'last_seen', label: 'last' }
      ]);
    };
    $('addFilter').onclick = () => addFilterRow();
    $('runQuery').onclick = runQuery;
    $('addSuspicious').onclick = () => api('/-/suspicious-ip', {
      method: 'POST',
      body: JSON.stringify({ ip_or_cidr: $('ipOrCidr').value.trim(), reason: $('reason').value.trim(), note: $('note').value.trim(), added_by: 'admin-page' })
    });
    $('deleteSuspicious').onclick = () => api('/-/suspicious-ip', {
      method: 'DELETE',
      body: JSON.stringify({ ip_or_cidr: $('ipOrCidr').value.trim() })
    });
    $('listSuspicious').onclick = async () => {
      const data = await api('/-/suspicious-ip');
      $('registryTable').innerHTML = table(data.entries || [], [
        { key: 'ip_or_cidr', label: 'ip/cidr' },
        { key: 'reason', label: 'reason' },
        { key: 'note', label: 'note', truncate: true },
        { key: 'added_by', label: 'by' },
        { key: 'added_at', label: 'added' },
        { key: 'enabled', label: 'on' }
      ]);
    };
    addFilterRow({ field: 'tenant_id', op: 'eq', value: '' });
    addFilterRow({ field: 'user_agent', op: 'ne', value: '' });
    status.textContent = 'Dashboard waits for manual refresh';
  </script>
</body>
</html>`;
}
