'use strict';

// Small in-memory fixed-window limiter. Fine for a single server process.
function createLimiter({ windowMs, max }) {
  const map = new Map();

  function live(key, now) {
    const e = map.get(key);
    if (e && e.resetAt > now) return e;
    if (e) map.delete(key);
    return null;
  }
  function sweep(now) {
    for (const [k, e] of map) if (e.resetAt <= now) map.delete(k);
  }

  return {
    // Seconds until allowed again if the key has already used up its quota, otherwise 0.
    peek(key, now = Date.now()) {
      const e = live(key, now);
      return e && e.count >= max ? Math.ceil((e.resetAt - now) / 1000) : 0;
    },
    // Records one use. Returns seconds to wait if this use went over the quota, otherwise 0.
    consume(key, now = Date.now()) {
      let e = live(key, now);
      if (!e) { e = { count: 0, resetAt: now + windowMs }; map.set(key, e); }
      e.count++;
      if (map.size > 20000) sweep(now);
      return e.count > max ? Math.ceil((e.resetAt - now) / 1000) : 0;
    },
    reset(key) { map.delete(key); }
  };
}

module.exports = { createLimiter };
