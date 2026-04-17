use std::collections::HashMap;

use anyhow::{anyhow, Result};

use crate::config::{AppConfig, RouteConfig};

#[derive(Debug, Clone)]
pub struct Router {
    default_pool: String,
    routes: Vec<RouteRule>,
}

#[derive(Debug, Clone)]
pub struct RouteSelection<'a> {
    pub target_pool: &'a str,
    pub upstream_path: String,
    pub matched_path_prefix: Option<&'a str>,
}

impl Router {
    pub fn from_config(config: &AppConfig) -> Result<Self> {
        let routes = config
            .routes
            .iter()
            .map(RouteRule::from_config)
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            default_pool: config.primary.name.clone(),
            routes,
        })
    }

    pub fn select<'a>(&'a self, host: &str, path: &str) -> RouteSelection<'a> {
        for route in &self.routes {
            if route.matches(host, path) {
                return RouteSelection {
                    target_pool: route.target_pool.as_str(),
                    upstream_path: route.rewrite_path(path),
                    matched_path_prefix: route.path_prefix.as_deref(),
                };
            }
        }

        RouteSelection {
            target_pool: self.default_pool.as_str(),
            upstream_path: path.to_string(),
            matched_path_prefix: None,
        }
    }

    pub fn validate_targets(
        &self,
        pools: &HashMap<String, crate::config::ClusterConfig>,
    ) -> Result<()> {
        if !pools.contains_key(&self.default_pool) {
            return Err(anyhow!("default pool {} does not exist", self.default_pool));
        }

        for route in &self.routes {
            if !pools.contains_key(&route.target_pool) {
                return Err(anyhow!(
                    "route target pool {} does not exist",
                    route.target_pool
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct RouteRule {
    host_equals: Option<String>,
    host_suffix: Option<String>,
    path_prefix: Option<String>,
    rewrite_prefix: Option<String>,
    target_pool: String,
}

impl RouteRule {
    fn from_config(config: &RouteConfig) -> Result<Self> {
        if config.host_equals.is_none()
            && config.host_suffix.is_none()
            && config.path_prefix.is_none()
        {
            return Err(anyhow!(
                "route targeting pool {} must define at least one matcher",
                config.target_pool
            ));
        }

        Ok(Self {
            host_equals: config
                .host_equals
                .as_ref()
                .map(|value| value.to_ascii_lowercase()),
            host_suffix: config
                .host_suffix
                .as_ref()
                .map(|value| value.to_ascii_lowercase()),
            path_prefix: config.path_prefix.clone(),
            rewrite_prefix: config.rewrite_prefix.clone(),
            target_pool: config.target_pool.clone(),
        })
    }

    fn matches(&self, host: &str, path: &str) -> bool {
        let host = crate::filters::normalize_host(host);

        if let Some(expected) = &self.host_equals {
            if host != *expected {
                return false;
            }
        }

        if let Some(suffix) = &self.host_suffix {
            if !host.ends_with(suffix) {
                return false;
            }
        }

        if let Some(prefix) = &self.path_prefix {
            if !path.starts_with(prefix) {
                return false;
            }
        }

        true
    }

    fn rewrite_path(&self, path: &str) -> String {
        match (&self.path_prefix, &self.rewrite_prefix) {
            (Some(prefix), Some(rewrite_prefix)) if path.starts_with(prefix) => {
                let suffix = &path[prefix.len()..];
                let mut rewritten = rewrite_prefix.clone();
                if !rewritten.ends_with('/') && !suffix.is_empty() && !suffix.starts_with('/') {
                    rewritten.push('/');
                }
                rewritten.push_str(suffix);
                if rewritten.is_empty() {
                    "/".to_string()
                } else {
                    rewritten
                }
            }
            _ => path.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::config::{
        AdaptiveDefenseConfig, AppConfig, BackendConfig, ClusterConfig, FilterConfig,
        HealthCheckConfig, InternalEndpointsConfig, MaintenanceConfig, RateLimitConfig,
        ResponseConfig, RouteConfig, ServerConfig, SinkholeConfig, TraceConfig,
    };

    use super::Router;

    fn app_config(routes: Vec<RouteConfig>) -> AppConfig {
        AppConfig {
            server: ServerConfig {
                response_server_header: "Backflow".to_string(),
                listeners: vec![crate::config::ListenerConfig {
                    addr: "127.0.0.1:8080".to_string(),
                    tls: None,
                }],
                trusted_proxies: Vec::new(),
                client_ip_headers: vec!["CF-Connecting-IP".to_string()],
                strict_proxy_headers: true,
            },
            primary: ClusterConfig {
                name: "origin".to_string(),
                host_header: "origin.internal".to_string(),
                sni: "origin.internal".to_string(),
                use_tls: false,
                preserve_original_host: true,
                peers: vec!["127.0.0.1:9000".to_string()],
            },
            pools: HashMap::from([(
                "api".to_string(),
                ClusterConfig {
                    name: "api".to_string(),
                    host_header: "api.internal".to_string(),
                    sni: "api.internal".to_string(),
                    use_tls: false,
                    preserve_original_host: true,
                    peers: vec!["127.0.0.1:9200".to_string()],
                },
            )]),
            routes,
            sinkhole: SinkholeConfig {
                enabled: false,
                mode: crate::config::SinkholeMode::Local,
                local_status: 200,
                local_body: "ok".to_string(),
                local_content_type: "text/plain".to_string(),
                local_headers: HashMap::new(),
                delay_ms: 0,
                jitter_ms: 0,
                cluster: None,
            },
            blackhole: crate::config::BlackholeConfig::default(),
            health_checks: HealthCheckConfig {
                enabled: false,
                frequency_secs: 5,
            },
            filters: toml::from_str::<FilterConfig>("").unwrap_or_else(|_| FilterConfig {
                default_action: crate::config::TrafficAction::Reject,
                allow_ips: Vec::new(),
                block_ips: Vec::new(),
                allow_hosts: Vec::new(),
                block_hosts: Vec::new(),
                allow_path_prefixes: Vec::new(),
                require_host_header: true,
                require_user_agent: false,
                allow_methods: vec!["GET".to_string()],
                block_user_agents: Vec::new(),
                block_header_names: Vec::new(),
                block_path_patterns: Vec::new(),
                block_path_suffixes: Vec::new(),
                block_file_extensions: Vec::new(),
                block_query_patterns: Vec::new(),
                block_query_keys: Vec::new(),
                trusted_user_agents: Vec::new(),
                skip_rate_limit_paths: Vec::new(),
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
                max_header_count: 96,
                max_header_bytes: 16384,
                max_path_length: 2048,
                max_path_segments: 48,
                max_query_length: 4096,
                max_query_params: 64,
                max_content_length: 8 * 1024 * 1024,
                max_empty_headers: 8,
                max_repeated_path_chars: 24,
                max_suspicion_score: 5,
                empty_user_agent_score: 1,
                odd_method_score: 2,
                encoded_path_score: 2,
                attack_path_score: 3,
                attack_query_score: 3,
                malformed_encoding_score: 2,
                suspicious_method_override_score: 2,
                header_spike_score: 2,
                query_spike_score: 2,
                empty_header_score: 1,
                blocked_ua_score: 3,
                repeated_path_score: 2,
                suspicious_header_score: 2,
                suspicious_query_key_score: 2,
                sensitive_extension_score: 3,
                reject_status: 403,
                reject_body: "blocked".to_string(),
            }),
            rate_limit: RateLimitConfig {
                enabled: false,
                requests_per_period: 120,
                burst: 240,
                period_secs: 10,
                exceeded_action: crate::config::TrafficAction::Reject,
                reject_status: 429,
                reject_body: "rate limit exceeded".to_string(),
            },
            adaptive: AdaptiveDefenseConfig {
                enabled: false,
                max_concurrent_requests_per_ip: 32,
                concurrency_action: crate::config::TrafficAction::Reject,
                strike_threshold: 6,
                ban_secs: 300,
                ban_action: crate::config::TrafficAction::Blackhole,
            },
            backend: BackendConfig::default(),
            trace: TraceConfig::default(),
            response: ResponseConfig::default(),
            maintenance: MaintenanceConfig::default(),
            internal_endpoints: InternalEndpointsConfig::default(),
            protected_paths: Vec::new(),
        }
    }

    #[test]
    fn route_rewrite_changes_upstream_path() {
        let router = Router::from_config(&app_config(vec![RouteConfig {
            target_pool: "api".to_string(),
            host_equals: None,
            host_suffix: None,
            path_prefix: Some("/api/".to_string()),
            rewrite_prefix: Some("/".to_string()),
        }]))
        .unwrap();

        let selection = router.select("example.com", "/api/users");
        assert_eq!(selection.target_pool, "api");
        assert_eq!(selection.upstream_path, "/users");
        assert_eq!(selection.matched_path_prefix, Some("/api/"));
    }

    #[test]
    fn default_route_keeps_original_path() {
        let router = Router::from_config(&app_config(vec![])).unwrap();

        let selection = router.select("example.com", "/healthz");
        assert_eq!(selection.target_pool, "origin");
        assert_eq!(selection.upstream_path, "/healthz");
        assert!(selection.matched_path_prefix.is_none());
    }
}
