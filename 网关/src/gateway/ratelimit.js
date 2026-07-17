// 按 client_ip 的令牌桶限流。内存实现，定期清理空闲桶。
export class RateLimiter {
  constructor({ enabled = false, requestsPerMinute = 120, burst = 40 } = {}) {
    this.enabled = enabled;
    this.ratePerMs = requestsPerMinute / 60000; // 每毫秒补充的令牌数
    this.capacity = burst;
    this.buckets = new Map(); // ip -> { tokens, last }
    this._sweepAt = Date.now();
  }

  // 返回 true 表示允许，false 表示超限。
  allow(ip) {
    if (!this.enabled) return true;
    const now = Date.now();
    let b = this.buckets.get(ip);
    if (!b) {
      b = { tokens: this.capacity, last: now };
      this.buckets.set(ip, b);
    }
    // 按经过时间补充令牌
    b.tokens = Math.min(this.capacity, b.tokens + (now - b.last) * this.ratePerMs);
    b.last = now;
    this._maybeSweep(now);
    if (b.tokens >= 1) {
      b.tokens -= 1;
      return true;
    }
    return false;
  }

  // 周期性清理已满（长时间空闲）的桶，防止内存无限增长。
  _maybeSweep(now) {
    if (now - this._sweepAt < 60000) return;
    this._sweepAt = now;
    for (const [ip, b] of this.buckets) {
      const refreshed = Math.min(this.capacity, b.tokens + (now - b.last) * this.ratePerMs);
      if (refreshed >= this.capacity) this.buckets.delete(ip);
    }
  }
}
