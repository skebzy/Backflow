use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use pingora_core::services::background::background_service;
use pingora_load_balancing::{health_check, selection::RoundRobin, LoadBalancer};

use crate::config::{ClusterConfig, HealthCheckConfig};

pub type SharedLoadBalancer = Arc<LoadBalancer<RoundRobin>>;

pub struct ClusterRuntime {
    pub load_balancer: SharedLoadBalancer,
    pub background: Option<Box<dyn pingora::services::ServiceWithDependents>>,
}

pub fn build_cluster(
    cluster: &ClusterConfig,
    health_checks: &HealthCheckConfig,
) -> Result<ClusterRuntime> {
    let mut upstreams = LoadBalancer::try_from_iter(cluster.peers.iter().map(String::as_str))
        .with_context(|| format!("failed to build load balancer for cluster {}", cluster.name))?;

    if health_checks.enabled {
        let hc = health_check::TcpHealthCheck::new();
        upstreams.set_health_check(hc);
        upstreams.health_check_frequency = Some(Duration::from_secs(health_checks.frequency_secs));
        let background = background_service(format!("{} health checks", cluster.name), upstreams);

        return Ok(ClusterRuntime {
            load_balancer: background.task(),
            background: Some(Box::new(background)),
        });
    }

    Ok(ClusterRuntime {
        load_balancer: Arc::new(upstreams),
        background: None,
    })
}
