import sys
import time
import threading

# Store buckets on sys module so they persist across WIZ exec() calls
_STORE_KEY = "_wiz_rate_limit_store"
_LOCK_KEY = "_wiz_rate_limit_lock"
_CLEANUP_KEY = "_wiz_rate_limit_last_cleanup"

MAX_BUCKETS = 2048
CLEANUP_INTERVAL_SECONDS = 60
STALE_BUCKET_SECONDS = 3600

if not hasattr(sys, _STORE_KEY):
    setattr(sys, _STORE_KEY, {})
if not hasattr(sys, _LOCK_KEY):
    setattr(sys, _LOCK_KEY, threading.Lock())
if not hasattr(sys, _CLEANUP_KEY):
    setattr(sys, _CLEANUP_KEY, 0.0)


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
    def _cleanup_locked(now, max_age_seconds=STALE_BUCKET_SECONDS, reserve_slot=False):
        buckets = RateLimiter._buckets()
        cutoff = now - max_age_seconds
        stale_keys = []
        for bucket_key, timestamps in buckets.items():
            valid = [timestamp for timestamp in timestamps if timestamp > cutoff]
            if valid:
                buckets[bucket_key] = valid
            else:
                stale_keys.append(bucket_key)
        for bucket_key in stale_keys:
            buckets.pop(bucket_key, None)

        target_size = MAX_BUCKETS - (1 if reserve_slot else 0)
        overflow = len(buckets) - target_size
        if overflow > 0:
            oldest = sorted(
                buckets,
                key=lambda bucket_key: max(buckets.get(bucket_key) or [0]),
            )[:overflow]
            for bucket_key in oldest:
                buckets.pop(bucket_key, None)
        setattr(sys, _CLEANUP_KEY, now)

    @staticmethod
    def _maybe_cleanup_locked(now, incoming_key=None):
        buckets = RateLimiter._buckets()
        last_cleanup = float(getattr(sys, _CLEANUP_KEY, 0.0) or 0.0)
        needs_slot = incoming_key is not None and incoming_key not in buckets
        if now - last_cleanup >= CLEANUP_INTERVAL_SECONDS or (
            needs_slot and len(buckets) >= MAX_BUCKETS
        ):
            RateLimiter._cleanup_locked(now, reserve_slot=needs_slot)

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
            RateLimiter._maybe_cleanup_locked(now, incoming_key=key)
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
            RateLimiter._maybe_cleanup_locked(now)
            if key not in buckets:
                return max_requests
            valid = [t for t in buckets[key] if t > cutoff]
            if valid:
                buckets[key] = valid
            else:
                buckets.pop(key, None)
            return max(0, max_requests - len(valid))

    @staticmethod
    def cleanup_stale(max_age_seconds=3600):
        """Remove stale bucket entries older than max_age_seconds."""
        now = time.time()
        lock = RateLimiter._lock()

        with lock:
            RateLimiter._cleanup_locked(now, max_age_seconds=max_age_seconds)

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
                setattr(sys, _CLEANUP_KEY, 0.0)


Model = RateLimiter
