use std::{collections::HashMap, env, path::PathBuf};

use anyhow::{Context, Result};
use pingora::prelude::Opt;
use pingora_core::{listeners::tls::TlsSettings, server::Server};

use crate::{config::AppConfig, proxy::BackflowProxy, routing::Router, sinkhole::build_cluster};

pub fn run() -> Result<()> {
    let config_path = env::var("BACKFLOW_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("config/backflow.toml"));
    let app_config = AppConfig::load(&config_path)?;

    let opt = Opt::parse_args();
    let mut server = Server::new(Some(opt)).context("failed to create Pingora server")?;
    server.bootstrap();

    let mut pool_configs = HashMap::new();
    pool_configs.insert(app_config.primary.name.clone(), app_config.primary.clone());
    for (name, pool) in &app_config.pools {
        pool_configs.insert(name.clone(), pool.clone());
    }

    let router = Router::from_config(&app_config)?;
    router.validate_targets(&pool_configs)?;

    let mut pools = HashMap::new();
    for (name, cluster) in &pool_configs {
        let runtime = build_cluster(cluster, &app_config.health_checks)?;
        if let Some(background) = runtime.background {
            server.add_boxed_service(background);
        }
        pools.insert(name.clone(), runtime.load_balancer);
    }

    let sinkhole = if app_config.sinkhole.enabled {
        Some(build_cluster(
            app_config
                .sinkhole
                .cluster
                .as_ref()
                .context("sinkhole is enabled but config is missing")?,
            &app_config.health_checks,
        )?)
    } else {
        None
    };

    let mut proxy = pingora_proxy::http_proxy_service(
        &server.configuration,
        BackflowProxy::new(
            &app_config,
            pools,
            pool_configs,
            sinkhole.as_ref().map(|runtime| runtime.load_balancer.clone()),
            router,
        ),
    );

    for listener in &app_config.server.listeners {
        match &listener.tls {
            Some(tls) => {
                let mut tls_settings =
                    TlsSettings::intermediate(&tls.cert_path, &tls.key_path).with_context(|| {
                        format!(
                            "failed to load listener TLS assets cert={} key={}",
                            tls.cert_path, tls.key_path
                        )
                    })?;
                if tls.enable_h2 {
                    tls_settings.enable_h2();
                }
                proxy.add_tls_with_settings(&listener.addr, None, tls_settings);
            }
            None => proxy.add_tcp(&listener.addr),
        }
    }

    server.add_service(proxy);

    if let Some(runtime) = sinkhole {
        if let Some(background) = runtime.background {
            server.add_boxed_service(background);
        }
    }

    server.run_forever()
}
