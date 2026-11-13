// SPDX-License-Identifier: Apache-2.0
//! Client-side sliding-window rate limiter (per provider).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    max: usize,
    window: Duration,
    hits: Mutex<VecDeque<Instant>>,
}

impl RateLimiter {
    pub fn new(max: usize, window: Duration) -> Self {
        Self { max, window, hits: Mutex::new(VecDeque::new()) }
    }

    /// Ok when a request may be made now; Err(seconds to wait) otherwise.
    pub fn try_acquire(&self, now: Instant) -> Result<(), u64> {
        let mut hits = self.hits.lock().map_err(|_| 60u64)?;
        while hits.front().is_some_and(|t| now.duration_since(*t) >= self.window) {
            hits.pop_front();
        }
        if hits.len() >= self.max {
            let oldest = *hits.front().expect("non-empty");
            let wait = self.window.saturating_sub(now.duration_since(oldest));
            return Err(wait.as_secs().max(1));
        }
        hits.push_back(now);
        Ok(())
    }

    /// Whether `n` requests could be made now, without using any slot.
    pub fn check(&self, now: Instant, n: usize) -> Result<(), u64> {
        let mut hits = self.hits.lock().map_err(|_| 60u64)?;
        while hits.front().is_some_and(|t| now.duration_since(*t) >= self.window) {
            hits.pop_front();
        }
        if hits.len() + n > self.max {
            let oldest = hits.get(hits.len() + n - self.max - 1).copied().unwrap_or(now);
            return Err(self.window.saturating_sub(now.duration_since(oldest)).as_secs().max(1));
        }
        Ok(())
    }

    /// Use `n` slots at once, or none.
    pub fn try_acquire_n(&self, now: Instant, n: usize) -> Result<(), u64> {
        let mut hits = self.hits.lock().map_err(|_| 60u64)?;
        while hits.front().is_some_and(|t| now.duration_since(*t) >= self.window) {
            hits.pop_front();
        }
        if hits.len() + n > self.max {
            let oldest = hits.get(hits.len() + n - self.max - 1).copied().unwrap_or(now);
            return Err(self.window.saturating_sub(now.duration_since(oldest)).as_secs().max(1));
        }
        for _ in 0..n {
            hits.push_back(now);
        }
        Ok(())
    }

    pub fn describe(&self) -> String {
        let secs = self.window.as_secs();
        match secs {
            1 => format!("{} per second", self.max),
            60 => format!("{} per minute", self.max),
            _ => format!("{} per {secs} s", self.max),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_within_the_window() {
        let l = RateLimiter::new(2, Duration::from_secs(60));
        let t = Instant::now();
        assert!(l.try_acquire(t).is_ok());
        assert!(l.try_acquire(t).is_ok());
        assert!(l.try_acquire(t + Duration::from_secs(10)).unwrap_err() >= 49);
        assert!(l.try_acquire(t + Duration::from_secs(61)).is_ok());
        assert_eq!(l.describe(), "2 per minute");

        let l = RateLimiter::new(4, Duration::from_secs(60));
        assert!(l.try_acquire(t).is_ok());
        assert!(l.check(t, 3).is_ok());
        assert!(l.check(t, 4).is_err());
        assert!(l.try_acquire_n(t, 4).is_err(), "all or nothing");
        assert!(l.try_acquire_n(t, 3).is_ok());
        assert!(l.try_acquire(t).is_err());
    }
}
