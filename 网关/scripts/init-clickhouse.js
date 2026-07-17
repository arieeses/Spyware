import fs from 'node:fs';
import yaml from 'js-yaml';

const configPath = process.env.SUB_GATEWAY_CONFIG || './config.yaml';
const sqlPath = process.argv[2] || './sql/clickhouse.sql';

function normalizeUrl(url) {
  return String(url || '').replace(/\/+$/, '');
}

function authHeaders(ch) {
  const headers = {};
  if (ch.username || ch.password) {
    headers.authorization = `Basic ${Buffer.from(`${ch.username || ''}:${ch.password || ''}`).toString('base64')}`;
  }
  return headers;
}

function statements(sql) {
  const out = [];
  let current = '';
  for (const line of sql.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('--')) continue;
    current += line + '\n';
    if (trimmed.endsWith(';')) {
      out.push(current.replace(/;\s*$/, '').trim());
      current = '';
    }
  }
  if (current.trim()) out.push(current.trim());
  return out;
}

async function exec(ch, sql) {
  const url = `${normalizeUrl(ch.url)}/?query=${encodeURIComponent(sql)}`;
  const resp = await fetch(url, { method: 'POST', headers: authHeaders(ch) });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`ClickHouse error ${resp.status}: ${text}`);
  }
}

async function main() {
  const cfg = yaml.load(fs.readFileSync(configPath, 'utf8'));
  const ch = cfg.analytics?.clickhouse || {};
  if (!ch.url) throw new Error('analytics.clickhouse.url is required in config');
  const sql = fs.readFileSync(sqlPath, 'utf8');
  const parts = statements(sql);
  for (const stmt of parts) {
    process.stdout.write(`Executing: ${stmt.split(/\s+/).slice(0, 6).join(' ')}...\n`);
    await exec(ch, stmt);
  }
  process.stdout.write(`ClickHouse initialized: ${parts.length} statements\n`);
}

main().catch((err) => {
  process.stderr.write(err.stack || err.message);
  process.stderr.write('\n');
  process.exit(1);
});
