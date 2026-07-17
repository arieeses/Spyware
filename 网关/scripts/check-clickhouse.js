import fs from 'node:fs';
import yaml from 'js-yaml';

const configPath = process.env.SUB_GATEWAY_CONFIG || './config.yaml';

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

async function main() {
  const cfg = yaml.load(fs.readFileSync(configPath, 'utf8'));
  const ch = cfg.analytics?.clickhouse || {};
  if (!ch.url) throw new Error('analytics.clickhouse.url is required in config');
  const url = `${normalizeUrl(ch.url)}/?query=${encodeURIComponent('SELECT 1 FORMAT JSONEachRow')}`;
  const resp = await fetch(url, { method: 'POST', headers: authHeaders(ch) });
  const text = await resp.text();
  if (!resp.ok) throw new Error(`ClickHouse error ${resp.status}: ${text}`);
  process.stdout.write(text);
}

main().catch((err) => {
  process.stderr.write(err.stack || err.message);
  process.stderr.write('\n');
  process.exit(1);
});
