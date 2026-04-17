use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Mutex, MutexGuard},
    time::Instant,
};

#[derive(Debug)]
pub struct RateLimiter {
    requests_per_period: u32,
    burst: u32,
    period_secs: u64,
    state: Mutex<HashMap<IpAddr, TokenBucket>>,
}

impl RateLimiter {
    pub fn new(requests_per_period: u32, burst: u32, period_secs: u64) -> Self {
        Self {
            requests_per_period,
            burst,
            period_secs,
            state: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut guard = self.lock_state();
        let bucket = guard.entry(ip).or_insert_with(|| TokenBucket {
            tokens: self.burst as f64,
            last_refill: now,
        });

        let refill_per_sec = self.requests_per_period as f64 / self.period_secs as f64;
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + (elapsed * refill_per_sec)).min(self.burst as f64);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return true;
        }

        false
    }

    fn lock_state(&self) -> MutexGuard<'_, HashMap<IpAddr, TokenBucket>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr, thread, time::Duration};

    use super::RateLimiter;

    #[test]
    fn allows_within_burst() {
        let limiter = RateLimiter::new(2, 3, 1);
        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(!limiter.allow(ip));
    }

    #[test]
    fn refills_over_time() {
        let limiter = RateLimiter::new(1, 1, 1);
        let ip = IpAddr::from_str("127.0.0.2").unwrap();

        assert!(limiter.allow(ip));
        assert!(!limiter.allow(ip));

        thread::sleep(Duration::from_millis(1100));

        assert!(limiter.allow(ip));
    }
}
