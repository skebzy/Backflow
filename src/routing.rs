use std::collections::HashMap;

use anyhow::{anyhow, Result};

use crate::config::{AppConfig, RouteConfig};

#[derive(Debug, Clone)]
pub struct Router {
    default_pool: String,
    routes: Vec<RouteRule>,
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

    pub fn select_pool<'a>(&'a self, host: &str, path: &str) -> &'a str {
        for route in &self.routes {
            if route.matches(host, path) {
                return route.target_pool.as_str();
            }
        }

        self.default_pool.as_str()
    }

    pub fn validate_targets(&self, pools: &HashMap<String, crate::config::ClusterConfig>) -> Result<()> {
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
            host_equals: config.host_equals.as_ref().map(|value| value.to_ascii_lowercase()),
            host_suffix: config.host_suffix.as_ref().map(|value| value.to_ascii_lowercase()),
            path_prefix: config.path_prefix.clone(),
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
}
