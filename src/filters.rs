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
    block_path_patterns: Vec<String>,
    block_query_patterns: Vec<String>,
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
            allow_methods: config
                .filters
                .allow_methods
                .iter()
                .map(|value| value.to_ascii_uppercase())
                .collect(),
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
            block_path_patterns: config
                .filters
                .block_path_patterns
                .iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            block_query_patterns: config
                .filters
                .block_query_patterns
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

        if self.config.reject_invalid_content_length && request.has_invalid_content_length {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                "invalid content-length header".to_string(),
            );
        }

        if self.config.reject_multiple_content_length_headers
            && request.content_length_header_count > 1
        {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                "multiple content-length headers detected".to_string(),
            );
        }

        if self.config.reject_multiple_transfer_encoding_headers
            && request.transfer_encoding_header_count > 1
        {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                "multiple transfer-encoding headers detected".to_string(),
            );
        }

        if self.config.reject_non_chunked_transfer_encoding
            && request.has_non_chunked_transfer_encoding
        {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                "non-chunked transfer-encoding detected".to_string(),
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

        if self.config.reject_invalid_path && !request.has_valid_path {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                "invalid request path".to_string(),
            );
        }

        if self.config.reject_malformed_encoding && request.has_malformed_encoding {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                "malformed percent-encoding detected".to_string(),
            );
        }

        if self.config.reject_path_traversal && request.has_path_traversal {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                "path traversal sequence detected".to_string(),
            );
        }

        if let Some(pattern) = request.blocked_path_pattern(&self.block_path_patterns) {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                format!("blocked path pattern detected: {pattern}"),
            );
        }

        if let Some(pattern) = request.blocked_query_pattern(&self.block_query_patterns) {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                format!("blocked query pattern detected: {pattern}"),
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

        if request.path_segment_count > self.config.max_path_segments {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                format!(
                    "path segment count {} exceeded limit {}",
                    request.path_segment_count, self.config.max_path_segments
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

        if request.query_param_count > self.config.max_query_params {
            return self.map_action(
                self.config.default_action,
                self.config.reject_status,
                self.config.reject_body.clone(),
                format!(
                    "query parameter count {} exceeded limit {}",
                    request.query_param_count, self.config.max_query_params
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
        let lower_user_agent = request.user_agent.to_ascii_lowercase();
        let lower_path = request.path.to_ascii_lowercase();
        let lower_query = request.query.to_ascii_lowercase();

        if self
            .trusted_user_agents
            .iter()
            .any(|needle| lower_user_agent.contains(needle))
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

        if lower_path.contains("%00")
            || lower_path.contains("%2f")
            || lower_path.contains("%5c")
        {
            score += self.config.encoded_path_score;
        }

        if request.has_malformed_encoding {
            score += self.config.malformed_encoding_score;
        }

        if request.empty_headers > 0 {
            score += self.config.empty_header_score;
        }

        if self
            .block_user_agents
            .iter()
            .any(|needle| lower_user_agent.contains(needle))
        {
            score += self.config.blocked_ua_score;
        }

        if longest_repeated_run(&request.path) >= self.config.max_repeated_path_chars {
            score += self.config.repeated_path_score;
        }

        if self
            .block_path_patterns
            .iter()
            .any(|pattern| lower_path.contains(pattern))
        {
            score += self.config.attack_path_score;
        }

        if self
            .block_query_patterns
            .iter()
            .any(|pattern| lower_query.contains(pattern))
        {
            score += self.config.attack_query_score;
        }

        if request.has_suspicious_method_override() {
            score += self.config.suspicious_method_override_score;
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
    pub query: String,
    pub query_len: usize,
    pub user_agent: String,
    pub host: String,
    pub header_count: usize,
    pub header_bytes: usize,
    pub content_length: u64,
    pub content_length_header_count: usize,
    pub has_invalid_content_length: bool,
    pub empty_headers: usize,
    pub host_header_count: usize,
    pub transfer_encoding_header_count: usize,
    pub has_non_chunked_transfer_encoding: bool,
    pub has_underscored_headers: bool,
    pub header_names: Vec<String>,
    pub has_conflicting_content_headers: bool,
    pub has_valid_host: bool,
    pub has_valid_path: bool,
    pub path_segment_count: usize,
    pub query_param_count: usize,
    pub has_path_traversal: bool,
    pub has_malformed_encoding: bool,
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

    fn blocked_path_pattern<'a>(&'a self, blocked_patterns: &'a [String]) -> Option<&'a str> {
        let lower_path = self.path.to_ascii_lowercase();
        blocked_patterns
            .iter()
            .find(|pattern| lower_path.contains(pattern.as_str()))
            .map(String::as_str)
    }

    fn blocked_query_pattern<'a>(&'a self, blocked_patterns: &'a [String]) -> Option<&'a str> {
        let lower_query = self.query.to_ascii_lowercase();
        blocked_patterns
            .iter()
            .find(|pattern| lower_query.contains(pattern.as_str()))
            .map(String::as_str)
    }

    fn has_suspicious_method_override(&self) -> bool {
        self.header_names.iter().any(|name| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "x-http-method-override"
                    | "x-http-method"
                    | "x-method-override"
                    | "x-original-method"
            )
        })
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

pub(crate) fn parse_ip_rules(values: &[String]) -> Vec<IpNet> {
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

pub(crate) fn has_malformed_percent_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return true;
            }
            index += 3;
            continue;
        }
        index += 1;
    }

    false
}

pub(crate) fn has_path_traversal(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "../",
        "..\\",
        "%2e%2e",
        "%2e/",
        ".%2e/",
        "%2e%2f",
        "%2e%5c",
        "..%2f",
        "..%5c",
        "%252e%252e",
        "..;/",
    ]
    .into_iter()
    .any(|pattern| lower.contains(pattern))
}

pub(crate) fn count_path_segments(value: &str) -> usize {
    value.split('/').filter(|segment| !segment.is_empty()).count()
}

pub(crate) fn count_query_params(value: &str) -> usize {
    if value.is_empty() {
        return 0;
    }

    value.split('&').filter(|segment| !segment.is_empty()).count()
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
                block_path_patterns: vec!["/.env".to_string()],
                block_query_patterns: vec!["union select".to_string()],
                trusted_user_agents: vec![],
                skip_rate_limit_paths: vec![],
                strip_connection_headers: true,
                reject_underscored_headers: true,
                reject_multiple_host_headers: true,
                reject_conflicting_content_headers: true,
                reject_invalid_host_header: true,
                reject_invalid_content_length: true,
                reject_multiple_content_length_headers: true,
                reject_multiple_transfer_encoding_headers: true,
                reject_non_chunked_transfer_encoding: true,
                reject_malformed_encoding: true,
                reject_path_traversal: true,
                reject_invalid_path: true,
                max_header_count: 32,
                max_header_bytes: 1024,
                max_path_length: 128,
                max_path_segments: 8,
                max_query_length: 128,
                max_query_params: 8,
                max_content_length: 1024,
                max_empty_headers: 2,
                max_repeated_path_chars: 12,
                max_suspicion_score: 3,
                empty_user_agent_score: 1,
                odd_method_score: 2,
                encoded_path_score: 2,
                attack_path_score: 3,
                attack_query_score: 3,
                malformed_encoding_score: 2,
                suspicious_method_override_score: 2,
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
            trace: crate::config::TraceConfig::default(),
            response: crate::config::ResponseConfig::default(),
            maintenance: crate::config::MaintenanceConfig::default(),
            internal_endpoints: crate::config::InternalEndpointsConfig::default(),
            protected_paths: vec![],
        }
    }

    fn request(ip: &str) -> RequestMeta {
        RequestMeta {
            client_ip: IpAddr::from_str(ip).unwrap(),
            method: "GET".to_string(),
            path: "/".to_string(),
            query: String::new(),
            query_len: 0,
            user_agent: "curl/8".to_string(),
            host: "example.com".to_string(),
            header_count: 8,
            header_bytes: 256,
            content_length: 0,
            content_length_header_count: 1,
            has_invalid_content_length: false,
            empty_headers: 0,
            host_header_count: 1,
            transfer_encoding_header_count: 0,
            has_non_chunked_transfer_encoding: false,
            has_underscored_headers: false,
            header_names: vec!["host".to_string(), "user-agent".to_string()],
            has_conflicting_content_headers: false,
            has_valid_host: true,
            has_valid_path: true,
            path_segment_count: 0,
            query_param_count: 0,
            has_path_traversal: false,
            has_malformed_encoding: false,
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

    #[test]
    fn path_traversal_is_rejected() {
        let engine = FilterEngine::new(&config());
        let mut req = request("10.0.0.5");
        req.path = "/../../etc/passwd".to_string();
        req.has_path_traversal = true;
        let decision = engine.evaluate(&req);
        assert!(matches!(decision, Decision::Reject { .. }));
    }

    #[test]
    fn blocked_query_pattern_is_rejected() {
        let engine = FilterEngine::new(&config());
        let mut req = request("10.0.0.6");
        req.query = "id=1 union select password from users".to_string();
        req.query_len = req.query.len();
        req.query_param_count = 1;
        let decision = engine.evaluate(&req);
        assert!(matches!(decision, Decision::Reject { .. }));
    }

    #[test]
    fn invalid_content_length_is_rejected() {
        let engine = FilterEngine::new(&config());
        let mut req = request("10.0.0.7");
        req.has_invalid_content_length = true;
        let decision = engine.evaluate(&req);
        assert!(matches!(decision, Decision::Reject { .. }));
    }
}
