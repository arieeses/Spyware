// 结构化 JSON 日志，输出到 stdout / stderr，交由外部收集。
import crypto from 'node:crypto';

function emit(stream, level, obj) {
  const line = JSON.stringify({ time: new Date().toISOString(), level, ...obj });
  stream.write(line + '\n');
}

export const logger = {
  info: (obj) => emit(process.stdout, 'info', obj),
  warn: (obj) => emit(process.stdout, 'warn', obj),
  error: (obj) => emit(process.stderr, 'error', obj),
  // 请求访问日志单独一个方法，语义清晰
  access: (obj) => emit(process.stdout, 'info', { type: 'access', ...obj }),
};

// 对 token 做 sha256，日志中永不记录明文 token。
export function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}
