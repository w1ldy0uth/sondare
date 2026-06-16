use std::time::{Duration, Instant};

/// Token bucket rate limiter. Call `take()` before sending each packet.
pub struct RateLimiter {
    tokens: f64,
    capacity: f64,
    refill_per_ns: f64,
    last: Instant,
}

impl RateLimiter {
    /// `pps` = max packets per second. `burst` = max tokens to accumulate (usually 1x–2x pps).
    pub fn new(pps: u32, burst: u32) -> Self {
        let capacity = burst as f64;
        Self {
            tokens: capacity,
            capacity,
            refill_per_ns: pps as f64 / 1_000_000_000.0,
            last: Instant::now(),
        }
    }

    /// Block until a token is available, then consume it.
    pub fn take(&mut self) {
        loop {
            self.refill();
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                return;
            }
            // Sleep for roughly the time needed to accumulate one token
            let ns_needed = (1.0 - self.tokens) / self.refill_per_ns;
            std::thread::sleep(Duration::from_nanos(ns_needed as u64));
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed_ns = now.duration_since(self.last).as_nanos() as f64;
        self.tokens = (self.tokens + elapsed_ns * self.refill_per_ns).min(self.capacity);
        self.last = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_rate() {
        // At 1000 pps, 5 tokens should take ~4ms (5 intervals of 1ms each,
        // but we start with a full bucket so first is free).
        let mut rl = RateLimiter::new(1000, 1);
        let start = Instant::now();
        for _ in 0..5 {
            rl.take();
        }
        let elapsed = start.elapsed();
        // Should be at least 4ms, allow generous upper bound for CI
        assert!(elapsed >= Duration::from_millis(3), "too fast: {elapsed:?}");
        assert!(elapsed < Duration::from_millis(50), "too slow: {elapsed:?}");
    }
}
