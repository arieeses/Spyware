export function normalizeAnalyticsPaths(value, ctx = 'analytics_paths') {
  if (value == null) return null;
  const list = Array.isArray(value) ? value : [value];
  const out = [];
  for (const item of list) {
    const path = String(item || '').trim();
    if (!path || !path.startsWith('/') || path.includes('?') || path.includes('#')) {
      throw new Error(`${ctx} invalid path: ${item}`);
    }
    out.push(path);
  }
  return Object.freeze([...new Set(out)]);
}

export function shouldAnalyzePath(origin, path) {
  const paths = origin?.analytics_paths;
  if (!paths) return true;
  return paths.includes(path);
}
