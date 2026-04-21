import sys
import time
import threading

# Store buckets on sys module so they persist across WIZ exec() calls
_STORE_KEY = "_wiz_rate_limit_store"
_LOCK_KEY = "_wiz_rate_limit_lock"

if not hasattr(sys, _STORE_KEY):
    setattr(sys, _STORE_KEY, {})
if not hasattr(sys, _LOCK_KEY):
    setattr(sys, _LOCK_KEY, threading.Lock())


class RateLimiter:
    """In-memory IP-based rate limiter using sliding window counters.

    Uses sys-level storage to persist across WIZ exec() reloads.
    """

    @staticmethod
    def _buckets():
        return getattr(sys, _STORE_KEY)

    @staticmethod
    def _lock():
        return getattr(sys, _LOCK_KEY)

    @staticmethod
    def check(key, max_requests=10, window_seconds=300):
        """
        Check if a request is allowed under rate limit.

        Args:
            key: Unique key for the limit (e.g., "login:{ip}" or "sp-register:{ip}")
            max_requests: Maximum requests allowed in the window
            window_seconds: Time window in seconds (default: 5 minutes)

        Returns:
            True if allowed, False if rate limited
        """
        now = time.time()
        cutoff = now - window_seconds
        buckets = RateLimiter._buckets()
        lock = RateLimiter._lock()

        with lock:
            if key not in buckets:
                buckets[key] = []

            # Remove expired entries
            buckets[key] = [t for t in buckets[key] if t > cutoff]

            if len(buckets[key]) >= max_requests:
                return False

            buckets[key].append(now)
            return True

    @staticmethod
    def remaining(key, max_requests=10, window_seconds=300):
        """Get remaining requests in current window."""
        now = time.time()
        cutoff = now - window_seconds
        buckets = RateLimiter._buckets()
        lock = RateLimiter._lock()

        with lock:
            if key not in buckets:
                return max_requests
            valid = [t for t in buckets[key] if t > cutoff]
            return max(0, max_requests - len(valid))

    @staticmethod
    def cleanup_stale(max_age_seconds=3600):
        """Remove stale bucket entries older than max_age_seconds."""
        now = time.time()
        cutoff = now - max_age_seconds
        buckets = RateLimiter._buckets()
        lock = RateLimiter._lock()

        with lock:
            stale_keys = []
            for key, timestamps in buckets.items():
                buckets[key] = [t for t in timestamps if t > cutoff]
                if not buckets[key]:
                    stale_keys.append(key)
            for key in stale_keys:
                del buckets[key]

    @staticmethod
    def reset(key=None):
        """Reset rate limit buckets. If key is provided, reset only that key."""
        buckets = RateLimiter._buckets()
        lock = RateLimiter._lock()
        with lock:
            if key:
                buckets.pop(key, None)
            else:
                buckets.clear()


Model = RateLimiter
