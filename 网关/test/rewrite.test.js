import { test } from 'node:test';
import assert from 'node:assert/strict';
import yaml from 'js-yaml';
import { rewriteSubscriptionBody } from '../src/gateway/rewrite.js';

function b64(text) {
  return Buffer.from(text, 'utf8').toString('base64');
}

function deb64(text) {
  return Buffer.from(text, 'base64').toString('utf8');
}

test('base64 vmess only rewrites node add host', () => {
  const vmess = {
    v: '2',
    ps: 'HK 01',
    add: 'real.example.com',
    port: '443',
    id: '00000000-0000-0000-0000-000000000000',
    host: 'ws-host.example.com',
    sni: 'sni.example.com',
  };
  const input = b64(`vmess://${b64(JSON.stringify(vmess))}\r\n`);
  const output = deb64(rewriteSubscriptionBody(Buffer.from(input), 'base64', 'decoy.example.com').toString());
  const rewritten = JSON.parse(deb64(output.slice('vmess://'.length).trim()));

  assert.equal(rewritten.add, 'decoy.example.com');
  assert.equal(rewritten.host, 'ws-host.example.com');
  assert.equal(rewritten.sni, 'sni.example.com');
});

test('clash only rewrites proxies server field', () => {
  const input = yaml.dump({
    proxies: [
      {
        name: 'HK 01',
        type: 'vmess',
        server: 'real.example.com',
        port: 443,
        servername: 'sni.example.com',
        'ws-opts': { headers: { Host: 'ws-host.example.com' } },
      },
    ],
    rules: ['DOMAIN,real.example.com,DIRECT'],
  });
  const output = rewriteSubscriptionBody(Buffer.from(input), 'clash', 'decoy.example.com').toString();
  const parsed = yaml.load(output);

  assert.equal(parsed.proxies[0].server, 'decoy.example.com');
  assert.equal(parsed.proxies[0].servername, 'sni.example.com');
  assert.equal(parsed.proxies[0]['ws-opts'].headers.Host, 'ws-host.example.com');
  assert.equal(parsed.rules[0], 'DOMAIN,real.example.com,DIRECT');
});

test('quantumultx only rewrites line endpoint host', () => {
  const input = b64('vmess=real.example.com:443,method=chacha20-poly1305,obfs-host=ws-host.example.com,tag=HK 01\r\n');
  const output = deb64(rewriteSubscriptionBody(Buffer.from(input), 'quantumultx', 'decoy.example.com').toString());

  assert.match(output, /^vmess=decoy\.example\.com:443,/);
  assert.match(output, /obfs-host=ws-host\.example\.com/);
});

test('singbox only rewrites outbound server field', () => {
  const input = JSON.stringify({
    outbounds: [
      {
        type: 'vless',
        tag: 'HK 01',
        server: 'real.example.com',
        server_port: 443,
        tls: { enabled: true, server_name: 'sni.example.com' },
        transport: { type: 'ws', headers: { Host: ['ws-host.example.com'] } },
      },
      { type: 'selector', tag: 'PROXY', outbounds: ['HK 01'] },
    ],
  });
  const output = rewriteSubscriptionBody(Buffer.from(input), 'singbox', 'decoy.example.com').toString();
  const parsed = JSON.parse(output);

  assert.equal(parsed.outbounds[0].server, 'decoy.example.com');
  assert.equal(parsed.outbounds[0].tls.server_name, 'sni.example.com');
  assert.deepEqual(parsed.outbounds[0].transport.headers.Host, ['ws-host.example.com']);
  assert.equal(parsed.outbounds[1].server, undefined);
});
