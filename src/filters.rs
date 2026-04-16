use std::{
    collections::HashSet,
    net::IpAddr,
    str::FromStr,
    sync::Arc,
};

use ipnet::IpNet;
use log::warn;

use crate::{
    config::{AppConfig, TrafficAction},
    rate_limit::RateLimiter,
};

#[derive(Debug, Clone)]
pub struct FilterEngine {
    allow_ips: Vec<IpNet>,
    block_ips: Vec<IpNet>,
    allow_hosts: HashSet<String>,
    block_hosts: HashSet<String>,
    allow_methods: HashSet<String>,
    block_user_agents: Vec<String>,
    block_header_names: HashSet<String>,
    trusted_user_agents: Vec<String>,
    skip_rate_limit_paths: Vec<String>,
    config: crate::config::FilterConfig,
    rate_limit: crate::config::RateLimitConfig,
    limiter: Option<Arc<RateLimiter>>,
}

impl FilterEngine {
    pub fn new(config: &AppConfig) -> Self {
        let allow_ips = parse_ip_rules(&config.filters.allow_ips);
        let block_ips = parse_ip_rules(&config.filters.block_ips);
        let limiter = if config.rate_limit.enabled {
            Some(Arc::new(RateLimiter::new(
                config.rate_limit.requests_per_period,
                config.rate_limit.burst,
                config.rate_limit.period_secs,
            )))
        } else {
            None
        };

        Self {
            allow_ips,
            block_ips,
            allow_hosts: normalize_set(&config.filters.allow_hosts),
            block_hosts: normalize_set(&config.filters.block_hosts),
            allow_methods: normalize_set(&config.filters.allow_methods),
            block_user_agents: config
                .filters
                .block_user_agents
                .iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            block_header_names: config
                .filters
                .block_header_names
                .iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            trusted_user_agents: config
                .filters
                .trusted_user_agents
                .iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            skip_rate_limit_paths: config.filters.skip_rate_limit_paths.clone(),
            config: config.filters.clone(),
            rate_limit: config.rate_limit.clone(),
            limiter,
        }
    }

    pub fn evaluate(&self, request: &RequestMeta) -> Decision {
        if self.allow_ips.iter().any(|rule| rule.contains(&request.client_ip)) {
            return Decision::allow();
        }

        if self.block_ips.iter().any(|rule| rule.contains(&request.client_ip)) {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                "ip was blocklisted".to_string(),
            );
        }

        if self.config.require_host_header && request.host.is_empty() {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                "missing host header".to_string(),
            );
        }

        if !self.allow_hosts.is_empty() && !self.allow_hosts.contains(&request.host_normalized()) {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                format!("host {} not allowed", request.host),
            );
        }

        if self.block_hosts.contains(&request.host_normalized()) {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                format!("host {} blocklisted", request.host),
            );
        }

        if !self.allow_methods.contains(&request.method.to_ascii_uppercase()) {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                format!("method {} not allowed", request.method),
            );
        }

        if self.config.reject_invalid_host_header && !request.has_valid_host {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                "invalid host header".to_string(),
            );
        }

        if self.config.reject_multiple_host_headers && request.host_header_count > 1 {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                "multiple host headers detected".to_string(),
            );
        }

        if self.config.reject_conflicting_content_headers
            && request.has_conflicting_content_headers
        {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                "conflicting transfer/content length headers".to_string(),
            );
        }

        if self.config.reject_underscored_headers && request.has_underscored_headers {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                "underscored header name detected".to_string(),
            );
        }

        if let Some(header) = request.blocked_header_name(&self.block_header_names) {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                format!("blocked header present: {header}"),
            );
        }

        if request.header_count > self.config.max_header_count {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                format!(
                    "header count {} exceeded limit {}",
                    request.header_count, self.config.max_header_count
                ),
            );
        }

        if request.header_bytes > self.config.max_header_bytes {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                format!(
                    "header bytes {} exceeded limit {}",
                    request.header_bytes, self.config.max_header_bytes
                ),
            );
        }

        if request.path.len() > self.config.max_path_length {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                format!(
                    "path length {} exceeded limit {}",
                    request.path.len(),
                    self.config.max_path_length
                ),
            );
        }

        if request.query_len > self.config.max_query_length {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                format!(
                    "query length {} exceeded limit {}",
                    request.query_len, self.config.max_query_length
                ),
            );
        }

        if request.content_length > self.config.max_content_length {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                format!(
                    "content length {} exceeded limit {}",
                    request.content_length, self.config.max_content_length
                ),
            );
        }

        if request.empty_headers > self.config.max_empty_headers {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                format!(
                    "empty headers {} exceeded limit {}",
                    request.empty_headers, self.config.max_empty_headers
                ),
            );
        }

        let suspicion = self.score_request(request);
        if suspicion >= self.config.max_suspicion_score {
            warn!(
                "suspicious request from {} triggered score {}",
                request.client_ip, suspicion
            );
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                format!("suspicion score {suspicion} exceeded threshold"),
            );
        }

        if let Some(limiter) = &self.limiter {
            if self
                .skip_rate_limit_paths
                .iter()
                .any(|prefix| request.path.starts_with(prefix))
            {
                return Decision::allow();
            }
            if !limiter.allow(request.client_ip) {
                return self.map_action(
                    self.rate_limit.exceeded_action,
                    self.rate_limit.reject_status,
                    self.rate_limit.reject_body.clone(),
                    "rate limit exceeded".to_string(),
                );
            }
        }

        Decision::allow()
    }

    fn score_request(&self, request: &RequestMeta) -> u32 {
        let mut score = 0;

        if self
            .trusted_user_agents
            .iter()
            .any(|needle| request.user_agent.to_ascii_lowercase().contains(needle))
        {
            return 0;
        }

        if request.user_agent.is_empty() {
            score += self.config.empty_user_agent_score;
        }

        if !matches!(
            request.method.as_str(),
            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
        ) {
            score += self.config.odd_method_score;
        }

        let lower_path = request.path.to_ascii_lowercase();
        if lower_path.contains("%00")
            || lower_path.contains("%2f")
            || lower_path.contains("%5c")
        {
            score += self.config.encoded_path_score;
        }

        if request.empty_headers > 0 {
            score += self.config.empty_header_score;
        }

        if self
            .block_user_agents
            .iter()
            .any(|needle| request.user_agent.to_ascii_lowercase().contains(needle))
        {
            score += self.config.blocked_ua_score;
        }

        if longest_repeated_run(&request.path) >= self.config.max_repeated_path_chars {
            score += self.config.repeated_path_score;
        }

        if request.header_count > (self.config.max_header_count / 2) {
            score += self.config.header_spike_score;
        }

        if request.query_len > (self.config.max_query_length / 2) {
            score += self.config.query_spike_score;
        }

        score
    }

    fn map_action(
        &self,
        action: TrafficAction,
        status: u16,
        body: String,
        reason: String,
    ) -> Decision {
        match action {
            TrafficAction::Reject => Decision::Reject {
                status,
                body,
                reason,
            },
            TrafficAction::Sinkhole => Decision::Sinkhole { reason },
            TrafficAction::Blackhole => Decision::Blackhole { reason },
        }
    }

    pub fn strip_connection_headers(&self) -> bool {
        self.config.strip_connection_headers
    }
}

#[derive(Debug, Clone)]
pub struct RequestMeta {
    pub client_ip: IpAddr,
    pub method: String,
    pub path: String,
    pub query_len: usize,
    pub user_agent: String,
    pub host: String,
    pub header_count: usize,
    pub header_bytes: usize,
    pub content_length: u64,
    pub empty_headers: usize,
    pub host_header_count: usize,
    pub has_underscored_headers: bool,
    pub header_names: Vec<String>,
    pub has_conflicting_content_headers: bool,
    pub has_valid_host: bool,
}

impl RequestMeta {
    fn host_normalized(&self) -> String {
        normalize_host(&self.host)
    }

    fn blocked_header_name(&self, blocked_headers: &HashSet<String>) -> Option<&str> {
        self.header_names
            .iter()
            .find(|name| blocked_headers.contains(&name.to_ascii_lowercase()))
            .map(String::as_str)
    }
}

#[derive(Debug, Clone)]
pub enum Decision {
    Allow,
    Reject {
        status: u16,
        body: String,
        reason: String,
    },
    Sinkhole {
        reason: String,
    },
    Blackhole {
        reason: String,
    },
}

impl Decision {
    pub fn allow() -> Self {
        Self::Allow
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Reject { .. } => "reject",
            Self::Sinkhole { .. } => "sinkhole",
            Self::Blackhole { .. } => "blackhole",
        }
    }

    pub fn is_sinkhole(&self) -> bool {
        matches!(self, Self::Sinkhole { .. })
    }

    pub fn reason(&self) -> &str {
        match self {
            Self::Allow => "allowed",
            Self::Reject { reason, .. } => reason,
            Self::Sinkhole { reason } => reason,
            Self::Blackhole { reason } => reason,
        }
    }
}

fn parse_ip_rules(values: &[String]) -> Vec<IpNet> {
    values
        .iter()
        .filter_map(|value| {
            IpNet::from_str(value)
                .ok()
                .or_else(|| IpAddr::from_str(value).ok().map(IpNet::from))
        })
        .collect()
}

fn normalize_set(values: &[String]) -> HashSet<String> {
    values.iter().map(|value| normalize_host(value)).collect()
}

pub(crate) fn normalize_host(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return String::new();
    }

    if let Some(stripped) = value.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return stripped[..end].to_ascii_lowercase();
        }
    }

    if let Some((host, port)) = value.rsplit_once(':') {
        if !host.contains(':') && port.chars().all(|ch| ch.is_ascii_digit()) {
            return host.to_ascii_lowercase();
        }
    }

    value.to_ascii_lowercase()
}

fn longest_repeated_run(value: &str) -> usize {
    let mut longest = 0usize;
    let mut current = 0usize;
    let mut last = '\0';

    for ch in value.chars() {
        if ch == last {
            current += 1;
        } else {
            current = 1;
            last = ch;
        }
        longest = longest.max(current);
    }

    longest
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr};
    use std::collections::HashMap;

    use crate::config::{
        AppConfig, ClusterConfig, FilterConfig, HealthCheckConfig, RateLimitConfig, ServerConfig,
        SinkholeConfig, TrafficAction,
    };

    use super::{Decision, FilterEngine, RequestMeta};

    fn config() -> AppConfig {
        AppConfig {
            server: ServerConfig {
                response_server_header: "Backflow".to_string(),
                listeners: vec![],
                trusted_proxies: vec![],
                client_ip_headers: vec!["CF-Connecting-IP".to_string()],
                strict_proxy_headers: true,
            },
            primary: ClusterConfig {
                name: "origin".to_string(),
                host_header: "origin.internal".to_string(),
                sni: "origin.internal".to_string(),
                use_tls: false,
                peers: vec!["127.0.0.1:9000".to_string()],
            },
            pools: HashMap::new(),
            routes: vec![],
            sinkhole: SinkholeConfig {
                enabled: true,
                cluster: Some(ClusterConfig {
                    name: "sinkhole".to_string(),
                    host_header: "sinkhole.internal".to_string(),
                    sni: "sinkhole.internal".to_string(),
                    use_tls: false,
                    peers: vec!["127.0.0.1:9100".to_string()],
                }),
            },
            health_checks: HealthCheckConfig {
                enabled: false,
                frequency_secs: 5,
            },
            filters: FilterConfig {
                default_action: TrafficAction::Reject,
                allow_ips: vec![],
                block_ips: vec!["10.0.0.1".to_string()],
                allow_hosts: vec![],
                block_hosts: vec![],
                require_host_header: true,
                allow_methods: vec!["GET".to_string(), "POST".to_string(), "HEAD".to_string()],
                block_user_agents: vec![],
                block_header_names: vec!["x-evil".to_string()],
                trusted_user_agents: vec![],
                skip_rate_limit_paths: vec![],
                strip_connection_headers: true,
                reject_underscored_headers: true,
                reject_multiple_host_headers: true,
                reject_conflicting_content_headers: true,
                reject_invalid_host_header: true,
                max_header_count: 32,
                max_header_bytes: 1024,
                max_path_length: 128,
                max_query_length: 128,
                max_content_length: 1024,
                max_empty_headers: 2,
                max_repeated_path_chars: 12,
                max_suspicion_score: 3,
                empty_user_agent_score: 1,
                odd_method_score: 2,
                encoded_path_score: 2,
                header_spike_score: 1,
                query_spike_score: 1,
                empty_header_score: 1,
                blocked_ua_score: 2,
                repeated_path_score: 2,
                reject_status: 403,
                reject_body: "blocked".to_string(),
            },
            rate_limit: RateLimitConfig {
                enabled: false,
                requests_per_period: 10,
                burst: 10,
                period_secs: 1,
                exceeded_action: TrafficAction::Sinkhole,
                reject_status: 429,
                reject_body: "slow down".to_string(),
            },
            adaptive: crate::config::AdaptiveDefenseConfig {
                enabled: false,
                max_concurrent_requests_per_ip: 8,
                concurrency_action: TrafficAction::Sinkhole,
                strike_threshold: 3,
                ban_secs: 60,
                ban_action: TrafficAction::Blackhole,
            },
            backend: crate::config::BackendConfig::default(),
        }
    }

    fn request(ip: &str) -> RequestMeta {
        RequestMeta {
            client_ip: IpAddr::from_str(ip).unwrap(),
            method: "GET".to_string(),
            path: "/".to_string(),
            query_len: 0,
            user_agent: "curl/8".to_string(),
            host: "example.com".to_string(),
            header_count: 8,
            header_bytes: 256,
            content_length: 0,
            empty_headers: 0,
            host_header_count: 1,
            has_underscored_headers: false,
            header_names: vec!["host".to_string(), "user-agent".to_string()],
            has_conflicting_content_headers: false,
            has_valid_host: true,
        }
    }

    #[test]
    fn blocklisted_ip_is_rejected() {
        let engine = FilterEngine::new(&config());
        let decision = engine.evaluate(&request("10.0.0.1"));
        assert!(matches!(decision, Decision::Reject { .. }));
    }

    #[test]
    fn suspicious_request_scores_high() {
        let engine = FilterEngine::new(&config());
        let mut req = request("10.0.0.2");
        req.method = "TRACE".to_string();
        req.user_agent.clear();
        let decision = engine.evaluate(&req);
        assert!(matches!(decision, Decision::Reject { .. }));
    }

    #[test]
    fn host_allowlist_is_enforced() {
        let mut cfg = config();
        cfg.filters.allow_hosts = vec!["allowed.example".to_string()];
        let engine = FilterEngine::new(&cfg);
        let decision = engine.evaluate(&request("10.0.0.3"));
        assert!(matches!(decision, Decision::Reject { .. }));
    }

    #[test]
    fn blocked_header_is_rejected() {
        let engine = FilterEngine::new(&config());
        let mut req = request("10.0.0.4");
        req.header_names.push("x-evil".to_string());
        let decision = engine.evaluate(&req);
        assert!(matches!(decision, Decision::Reject { .. }));
    }
}
