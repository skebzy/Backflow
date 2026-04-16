use std::{collections::HashMap, fs, path::Path};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub primary: ClusterConfig,
    #[serde(default)]
    pub pools: HashMap<String, ClusterConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    pub sinkhole: SinkholeConfig,
    pub health_checks: HealthCheckConfig,
    pub filters: FilterConfig,
    pub rate_limit: RateLimitConfig,
    pub adaptive: AdaptiveDefenseConfig,
    #[serde(default)]
    pub backend: BackendConfig,
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let config: Self =
            toml::from_str(&contents).context("failed to parse backflow TOML config")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.server.listeners.is_empty() {
            bail!("at least one listener must be configured");
        }

        self.primary.validate("primary")?;

        for (name, pool) in &self.pools {
            pool.validate(name)?;
        }

        if self.sinkhole.enabled {
            let cluster = self
                .sinkhole
                .cluster
                .as_ref()
                .context("sinkhole.enabled is true but sinkhole cluster settings are missing")?;
            cluster.validate("sinkhole")?;
        }

        if self.rate_limit.enabled && self.rate_limit.period_secs == 0 {
            bail!("rate_limit.period_secs must be greater than zero");
        }

        if !self.server.trusted_proxies.is_empty() && self.server.client_ip_headers.is_empty() {
            bail!("server.client_ip_headers must not be empty when trusted_proxies are configured");
        }

        if self.adaptive.enabled && self.adaptive.max_concurrent_requests_per_ip == 0 {
            bail!("adaptive.max_concurrent_requests_per_ip must be greater than zero");
        }

        if self.adaptive.enabled && self.adaptive.strike_threshold == 0 {
            bail!("adaptive.strike_threshold must be greater than zero");
        }

        if self.filters.max_suspicion_score == 0 {
            bail!("filters.max_suspicion_score must be greater than zero");
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub response_server_header: String,
    pub listeners: Vec<ListenerConfig>,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default = "default_client_ip_headers")]
    pub client_ip_headers: Vec<String>,
    #[serde(default)]
    pub strict_proxy_headers: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
    pub addr: String,
    pub tls: Option<TlsListenerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsListenerConfig {
    pub cert_path: String,
    pub key_path: String,
    #[serde(default = "default_true")]
    pub enable_h2: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClusterConfig {
    pub name: String,
    pub host_header: String,
    pub sni: String,
    #[serde(default)]
    pub use_tls: bool,
    pub peers: Vec<String>,
}

impl ClusterConfig {
    fn validate(&self, label: &str) -> Result<()> {
        if self.peers.is_empty() {
            bail!("{label} cluster must have at least one peer");
        }
        if self.host_header.trim().is_empty() {
            bail!("{label} cluster host_header cannot be empty");
        }
        if self.use_tls && self.sni.trim().is_empty() {
            bail!("{label} cluster sni cannot be empty when use_tls is true");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SinkholeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(flatten)]
    pub cluster: Option<ClusterConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthCheckConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_health_frequency")]
    pub frequency_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FilterConfig {
    #[serde(default = "default_filter_action")]
    pub default_action: TrafficAction,
    #[serde(default)]
    pub allow_ips: Vec<String>,
    #[serde(default)]
    pub block_ips: Vec<String>,
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    #[serde(default)]
    pub block_hosts: Vec<String>,
    #[serde(default = "default_true")]
    pub require_host_header: bool,
    #[serde(default = "default_allowed_methods")]
    pub allow_methods: Vec<String>,
    #[serde(default)]
    pub block_user_agents: Vec<String>,
    #[serde(default)]
    pub block_header_names: Vec<String>,
    #[serde(default)]
    pub trusted_user_agents: Vec<String>,
    #[serde(default)]
    pub skip_rate_limit_paths: Vec<String>,
    #[serde(default = "default_true")]
    pub strip_connection_headers: bool,
    #[serde(default = "default_true")]
    pub reject_underscored_headers: bool,
    #[serde(default = "default_true")]
    pub reject_multiple_host_headers: bool,
    #[serde(default = "default_true")]
    pub reject_conflicting_content_headers: bool,
    #[serde(default = "default_true")]
    pub reject_invalid_host_header: bool,
    #[serde(default = "default_max_header_count")]
    pub max_header_count: usize,
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    #[serde(default = "default_max_path_length")]
    pub max_path_length: usize,
    #[serde(default = "default_max_query_length")]
    pub max_query_length: usize,
    #[serde(default = "default_max_content_length")]
    pub max_content_length: u64,
    #[serde(default = "default_max_empty_headers")]
    pub max_empty_headers: usize,
    #[serde(default = "default_max_repeated_path_chars")]
    pub max_repeated_path_chars: usize,
    #[serde(default = "default_suspicion_score")]
    pub max_suspicion_score: u32,
    #[serde(default)]
    pub empty_user_agent_score: u32,
    #[serde(default)]
    pub odd_method_score: u32,
    #[serde(default)]
    pub encoded_path_score: u32,
    #[serde(default)]
    pub header_spike_score: u32,
    #[serde(default)]
    pub query_spike_score: u32,
    #[serde(default)]
    pub empty_header_score: u32,
    #[serde(default)]
    pub blocked_ua_score: u32,
    #[serde(default)]
    pub repeated_path_score: u32,
    #[serde(default = "default_reject_status")]
    pub reject_status: u16,
    #[serde(default = "default_reject_body")]
    pub reject_body: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
    pub target_pool: String,
    pub host_equals: Option<String>,
    pub host_suffix: Option<String>,
    pub path_prefix: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_requests_per_period")]
    pub requests_per_period: u32,
    #[serde(default = "default_burst")]
    pub burst: u32,
    #[serde(default = "default_period_secs")]
    pub period_secs: u64,
    #[serde(default = "default_filter_action")]
    pub exceeded_action: TrafficAction,
    #[serde(default = "default_rate_limit_status")]
    pub reject_status: u16,
    #[serde(default = "default_rate_limit_body")]
    pub reject_body: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdaptiveDefenseConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_concurrent_per_ip")]
    pub max_concurrent_requests_per_ip: usize,
    #[serde(default = "default_concurrency_action")]
    pub concurrency_action: TrafficAction,
    #[serde(default = "default_strike_threshold")]
    pub strike_threshold: u32,
    #[serde(default = "default_ban_secs")]
    pub ban_secs: u64,
    #[serde(default = "default_ban_action")]
    pub ban_action: TrafficAction,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BackendConfig {
    #[serde(default)]
    pub inject_headers: HashMap<String, String>,
    #[serde(default = "default_strip_inbound_internal_headers")]
    pub strip_inbound_internal_headers: Vec<String>,
    #[serde(default = "default_true")]
    pub set_forwarded_port: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TrafficAction {
    Reject,
    Sinkhole,
    Blackhole,
}

fn default_true() -> bool {
    true
}

fn default_health_frequency() -> u64 {
    5
}

fn default_filter_action() -> TrafficAction {
    TrafficAction::Reject
}

fn default_max_header_count() -> usize {
    96
}

fn default_max_header_bytes() -> usize {
    16 * 1024
}

fn default_max_path_length() -> usize {
    2048
}

fn default_max_query_length() -> usize {
    4096
}

fn default_max_content_length() -> u64 {
    8 * 1024 * 1024
}

fn default_max_empty_headers() -> usize {
    8
}

fn default_max_repeated_path_chars() -> usize {
    24
}

fn default_suspicion_score() -> u32 {
    5
}

fn default_reject_status() -> u16 {
    403
}

fn default_reject_body() -> String {
    "blocked by backflow".to_string()
}

fn default_requests_per_period() -> u32 {
    120
}

fn default_burst() -> u32 {
    240
}

fn default_period_secs() -> u64 {
    10
}

fn default_rate_limit_status() -> u16 {
    429
}

fn default_rate_limit_body() -> String {
    "rate limit exceeded".to_string()
}

fn default_allowed_methods() -> Vec<String> {
    ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_client_ip_headers() -> Vec<String> {
    [
        "CF-Connecting-IPv6",
        "CF-Connecting-IP",
        "True-Client-IP",
        "X-Forwarded-For",
        "X-Real-IP",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_strip_inbound_internal_headers() -> Vec<String> {
    [
        "X-Backflow-Client-IP",
        "X-Backflow-Decision",
        "X-Backflow-Pool",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Forwarded-Port",
        "X-Real-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
        "CF-Connecting-IPv6",
        "Forwarded",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_max_concurrent_per_ip() -> usize {
    32
}

fn default_concurrency_action() -> TrafficAction {
    TrafficAction::Sinkhole
}

fn default_strike_threshold() -> u32 {
    6
}

fn default_ban_secs() -> u64 {
    300
}

fn default_ban_action() -> TrafficAction {
    TrafficAction::Blackhole
}
