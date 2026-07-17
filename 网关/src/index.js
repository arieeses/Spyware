// 鍏ュ彛锛氬姞杞介厤缃瀯寤鸿繍琛屾€侊紝鍚姩瀵瑰(HTTP/HTTPS)鏈嶅姟涓庡唴閮ㄦ湇鍔★紝
// 澶勭悊 SIGHUP 鐑噸杞姐€丼IGTERM/SIGINT 浼橀泤鍏抽棴銆?import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { buildState, StateHolder } from './state.js';
import { createHandler } from './gateway/handler.js';
import { createInternalHandler } from './gateway/internal.js';
import { AnalyticsWriter } from './analytics/writer.js';
import { logger } from './logger.js';

const CONFIG_PATH = process.env.SUB_GATEWAY_CONFIG || './config.yaml';

function parseListen(listen) {
  // "0.0.0.0:8443" / "127.0.0.1:8081" / "[::]:8443"
  const s = String(listen);
  const idx = s.lastIndexOf(':');
  const host = s.slice(0, idx).replace(/^\[|\]$/g, '');
  const port = parseInt(s.slice(idx + 1), 10);
  return { host: host || '0.0.0.0', port };
}

async function main() {
  let state;
  try {
    state = await buildState(CONFIG_PATH);
  } catch (err) {
    logger.error({ msg: 'startup_failed', error: err.message });
    process.exit(1);
  }
  const holder = new StateHolder(state);
  const cfg = state.config;
  const analytics = new AnalyticsWriter(cfg.analytics);
  let suspiciousRefreshAt = 0;

  // 瀵瑰鏈嶅姟锛氭寜 _listeners 閫愪釜鍒涘缓 server锛屽叏閮ㄥ叡鐢ㄥ悓涓€ handler / holder
  const handler = createHandler(holder, { analytics });
  const publicServers = [];
  for (const l of cfg.server._listeners) {
    let srv;
    if (l.tls?.enabled) {
      srv = https.createServer(
        { cert: fs.readFileSync(l.tls.cert_path), key: fs.readFileSync(l.tls.key_path) },
        handler,
      );
    } else {
      srv = http.createServer(handler);
    }
    srv.on('clientError', (err, socket) => {
      if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    });
    const { host, port } = parseListen(l.addr);
    srv.listen(port, host, () => {
      logger.info({ msg: 'public_listening', host, port, tls: !!l.tls?.enabled });
    });
    publicServers.push(srv);
  }

  // 鍐呴儴鏈嶅姟锛堝彲閫夛級
  let internalServer = null;
  if (cfg.server.internal_listen) {
    const reloadFn = async () => reload(holder);
    const internalHandler = createInternalHandler(holder, reloadFn);
    internalServer = http.createServer(internalHandler);
    const intl = parseListen(cfg.server.internal_listen);
    internalServer.listen(intl.port, intl.host, () => {
      logger.info({ msg: 'internal_listening', host: intl.host, port: intl.port });
    });
  }

  // 鐑噸杞斤細鍔犺浇鏂伴厤缃瀯寤烘柊鐘舵€侊紝鎴愬姛鍚庡師瀛愭浛鎹紱澶辫触淇濈暀鏃х姸鎬併€?
  async function reload(h) {
    logger.info({ msg: 'reload_start' });
    const next = await buildState(CONFIG_PATH); // 鎶涢敊鍒欎笉鏇挎崲
    h.swap(next);
    analytics.updateConfig(next.config.analytics);
    logger.info({ msg: 'reload_done', loaded_at: next.loadedAt });
  }

  process.on('SIGHUP', () => {
    reload(holder).catch((err) => logger.error({ msg: 'reload_error', error: err.message }));
  });

  const suspiciousRefreshTimer = setInterval(() => {
    const current = holder.current;
    const cfgNow = current.config.suspicious_ip || {};
    if (!cfgNow.enabled) return;
    const intervalMs = (cfgNow.refresh_interval_seconds || 30) * 1000;
    const now = Date.now();
    if (now - suspiciousRefreshAt < intervalMs) return;
    suspiciousRefreshAt = now;
    current.suspiciousIpRegistry?.refresh().catch((err) => {
      logger.warn({ msg: 'suspicious_ip_refresh_error', error: err.message });
    });
  }, 1000);
  suspiciousRefreshTimer.unref?.();

  // 浼橀泤鍏抽棴
  let shuttingDown = false;
  const shutdown = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ msg: 'shutdown_start', signal });
    const timer = setTimeout(() => {
      logger.warn({ msg: 'shutdown_forced' });
      process.exit(0);
    }, 15000);
    let pending = publicServers.length + (internalServer ? 1 : 0);
    const done = () => {
      pending--;
      if (pending <= 0) {
        analytics.close().catch((err) => logger.warn({ msg: 'analytics_close_error', error: err.message })).finally(() => {
          clearInterval(suspiciousRefreshTimer);
          clearTimeout(timer);
          logger.info({ msg: 'shutdown_done' });
          process.exit(0);
        });
      }
    };
    for (const s of publicServers) s.close(done);
    if (internalServer) internalServer.close(done);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main();
