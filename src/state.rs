use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

use crate::config::{AdaptiveDefenseConfig, TrafficAction};

#[derive(Debug)]
pub struct DefenseState {
    config: AdaptiveDefenseConfig,
    inner: Mutex<StateInner>,
}

impl DefenseState {
    pub fn new(config: AdaptiveDefenseConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(StateInner::default()),
        }
    }

    pub fn start_request(&self, ip: IpAddr) -> StateDecision {
        if !self.config.enabled {
            return StateDecision::Allow {
                counted: false,
                reason: "adaptive defense disabled".to_string(),
            };
        }

        let now = Instant::now();
        let mut inner = self.lock();
        inner.prune(now);

        if let Some(until) = inner.bans.get(&ip) {
            if *until > now {
                return StateDecision::action(
                    self.config.ban_action,
                    format!("temporary ban active until {:?}", until),
                );
            }
        }

        let active = inner.active.entry(ip).or_insert(0);
        if *active >= self.config.max_concurrent_requests_per_ip {
            return StateDecision::action(
                self.config.concurrency_action,
                format!(
                    "concurrent request limit {} exceeded",
                    self.config.max_concurrent_requests_per_ip
                ),
            );
        }

        *active += 1;
        StateDecision::Allow {
            counted: true,
            reason: "request admitted".to_string(),
        }
    }

    pub fn finish_request(&self, ip: IpAddr) {
        if !self.config.enabled {
            return;
        }

        let mut inner = self.lock();
        if let Some(active) = inner.active.get_mut(&ip) {
            if *active > 1 {
                *active -= 1;
            } else {
                inner.active.remove(&ip);
            }
        }
    }

    pub fn record_infraction(&self, ip: IpAddr, reason: &str) -> bool {
        if !self.config.enabled {
            return false;
        }

        let now = Instant::now();
        let mut inner = self.lock();
        inner.prune(now);

        let entry = inner.strikes.entry(ip).or_insert(StrikeState {
            count: 0,
            last_seen: now,
        });
        entry.count += 1;
        entry.last_seen = now;

        if entry.count >= self.config.strike_threshold {
            inner
                .bans
                .insert(ip, now + Duration::from_secs(self.config.ban_secs));
            inner.strikes.remove(&ip);
            log::warn!("temporary ban activated for {ip} after infraction: {reason}");
            return true;
        }

        false
    }

    fn lock(&self) -> MutexGuard<'_, StateInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Debug)]
pub enum StateDecision {
    Allow { counted: bool, reason: String },
    Reject { reason: String },
    Sinkhole { reason: String },
    Blackhole { reason: String },
}

impl StateDecision {
    fn action(action: TrafficAction, reason: String) -> Self {
        match action {
            TrafficAction::Reject => Self::Reject { reason },
            TrafficAction::Sinkhole => Self::Sinkhole { reason },
            TrafficAction::Blackhole => Self::Blackhole { reason },
        }
    }
}

#[derive(Debug, Default)]
struct StateInner {
    active: HashMap<IpAddr, usize>,
    strikes: HashMap<IpAddr, StrikeState>,
    bans: HashMap<IpAddr, Instant>,
}

impl StateInner {
    fn prune(&mut self, now: Instant) {
        self.bans.retain(|_, until| *until > now);

        let strike_window = Duration::from_secs(900);
        self.strikes
            .retain(|_, strike| now.duration_since(strike.last_seen) < strike_window);
    }
}

#[derive(Debug)]
struct StrikeState {
    count: u32,
    last_seen: Instant,
}
