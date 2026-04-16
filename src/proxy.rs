use std::{collections::HashMap, net::IpAddr, str::FromStr, sync::Arc};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use ipnet::IpNet;
use log::{info, warn};
use pingora_core::{upstreams::peer::HttpPeer, Error};
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};

use crate::{
    config::{AppConfig, ClusterConfig},
    filters::{Decision, FilterEngine, RequestMeta},
    routing::Router,
    sinkhole::SharedLoadBalancer,
    state::{DefenseState, StateDecision},
};

pub struct BackflowProxy {
    engine: Arc<FilterEngine>,
    default_pool: String,
    pools: HashMap<String, SharedLoadBalancer>,
    sinkhole_lb: Option<SharedLoadBalancer>,
    pool_configs: HashMap<String, ClusterConfig>,
    sinkhole_cluster: Option<ClusterConfig>,
    server_header: String,
    state: Arc<DefenseState>,
    router: Arc<Router>,
    trusted_proxies: Vec<IpNet>,
    client_ip_headers: Vec<String>,
    strict_proxy_headers: bool,
    backend_headers: HashMap<String, String>,
    strip_inbound_internal_headers: Vec<String>,
    set_forwarded_port: bool,
}

impl BackflowProxy {
    pub fn new(
        config: &AppConfig,
        pools: HashMap<String, SharedLoadBalancer>,
        pool_configs: HashMap<String, ClusterConfig>,
        sinkhole_lb: Option<SharedLoadBalancer>,
        router: Router,
    ) -> Self {
        Self {
            engine: Arc::new(FilterEngine::new(config)),
            default_pool: config.primary.name.clone(),
            pools,
            sinkhole_lb,
            pool_configs,
            sinkhole_cluster: config.sinkhole.cluster.clone(),
            server_header: config.server.response_server_header.clone(),
            state: Arc::new(DefenseState::new(config.adaptive.clone())),
            router: Arc::new(router),
            trusted_proxies: config
                .server
                .trusted_proxies
                .iter()
                .filter_map(|value| {
                    IpNet::from_str(value)
                        .ok()
                        .or_else(|| IpAddr::from_str(value).ok().map(IpNet::from))
                })
                .collect(),
            client_ip_headers: config.server.client_ip_headers.clone(),
            strict_proxy_headers: config.server.strict_proxy_headers,
            backend_headers: config.backend.inject_headers.clone(),
            strip_inbound_internal_headers: config.backend.strip_inbound_internal_headers.clone(),
            set_forwarded_port: config.backend.set_forwarded_port,
        }
    }

    fn request_meta(session: &Session) -> Result<RequestMeta> {
        let peer_ip = session
            .client_addr()
            .map(|addr| addr.ip())
            .ok_or_else(|| anyhow!("failed to read client address from session"))?;
        let req = session.req_header();
        let path = req.uri.path().to_string();
        let query_len = req.uri.query().map_or(0, str::len);
        let method = req.method.as_str().to_string();
        let host = req
            .headers
            .get("Host")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let user_agent = req
            .headers
            .get("User-Agent")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let header_count = req.headers.len();
        let header_bytes = req
            .headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
            .sum();
        let empty_headers = req
            .headers
            .iter()
            .filter(|(_, value)| value.as_bytes().is_empty())
            .count();
        let content_length = req
            .headers
            .get("Content-Length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let has_transfer_encoding = req.headers.contains_key("Transfer-Encoding");
        let host_header_count = req.headers.get_all("Host").iter().count();
        let header_names = req
            .headers
            .iter()
            .map(|(name, _)| name.as_str().to_string())
            .collect::<Vec<_>>();
        let has_underscored_headers = header_names.iter().any(|name| name.contains('_'));
        let normalized_host = crate::filters::normalize_host(&host);
        let has_valid_host = !normalized_host.is_empty()
            && normalized_host
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | ':' ));

        Ok(RequestMeta {
            client_ip: peer_ip,
            method,
            path,
            query_len,
            user_agent,
            host,
            header_count,
            header_bytes,
            content_length,
            empty_headers,
            host_header_count,
            has_underscored_headers,
            header_names,
            has_conflicting_content_headers: has_transfer_encoding && content_length > 0,
            has_valid_host,
        })
    }

    fn cluster_for<'a>(
        &'a self,
        decision: &Decision,
    ) -> Result<(&'a ClusterConfig, &'a SharedLoadBalancer)> {
        if decision.is_sinkhole() {
            let cluster = self
                .sinkhole_cluster
                .as_ref()
                .ok_or_else(|| anyhow!("sinkhole decision reached but sinkhole cluster is missing"))?;
            let lb = self
                .sinkhole_lb
                .as_ref()
                .ok_or_else(|| anyhow!("sinkhole decision reached but sinkhole load balancer is missing"))?;
            return Ok((cluster, lb));
        }

        let cluster = self
            .pool_configs
            .get(&self.default_pool)
            .ok_or_else(|| anyhow!("default pool {} is missing", self.default_pool))?;
        let lb = self
            .pools
            .get(&self.default_pool)
            .ok_or_else(|| anyhow!("default load balancer {} is missing", self.default_pool))?;
        Ok((cluster, lb))
    }

    fn to_pingora_error(error: anyhow::Error) -> Box<Error> {
        Error::because(pingora_core::ErrorType::InternalError, "backflow error", error)
    }

    fn extract_client_ip(&self, session: &Session, request: &RequestMeta) -> IpAddr {
        if !self
            .trusted_proxies
            .iter()
            .any(|network| network.contains(&request.client_ip))
        {
            return request.client_ip;
        }

        for header in &self.client_ip_headers {
            let value = session.req_header().headers.get(header.as_str());
            let parsed = match header.to_ascii_lowercase().as_str() {
                "x-forwarded-for" => value
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.split(',').next())
                    .and_then(|value| IpAddr::from_str(value.trim()).ok()),
                _ => value
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| IpAddr::from_str(value.trim()).ok()),
            };

            if let Some(ip) = parsed {
                return ip;
            }

            if self.strict_proxy_headers && value.is_some() {
                return request.client_ip;
            }
        }

        request.client_ip
    }

    fn selected_cluster_for<'a>(
        &'a self,
        ctx: &RequestContext,
    ) -> Result<(&'a ClusterConfig, &'a SharedLoadBalancer)> {
        let cluster = self
            .pool_configs
            .get(&ctx.selected_pool)
            .ok_or_else(|| anyhow!("selected pool {} is missing config", ctx.selected_pool))?;
        let lb = self
            .pools
            .get(&ctx.selected_pool)
            .ok_or_else(|| anyhow!("selected pool {} is missing balancer", ctx.selected_pool))?;
        Ok((cluster, lb))
    }
}

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub client_ip: Option<IpAddr>,
    pub host: String,
    pub path: String,
    pub decision: Decision,
    pub counted_concurrency: bool,
    pub selected_pool: String,
}

#[async_trait]
impl ProxyHttp for BackflowProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext {
            client_ip: None,
            host: String::new(),
            path: String::new(),
            decision: Decision::allow(),
            counted_concurrency: false,
            selected_pool: String::new(),
        }
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<bool> {
        let request = Self::request_meta(session).map_err(Self::to_pingora_error)?;
        let client_ip = self.extract_client_ip(session, &request);
        let mut request = request;
        request.client_ip = client_ip;
        ctx.client_ip = Some(client_ip);
        ctx.host = request.host.clone();
        ctx.path = request.path.clone();
        ctx.selected_pool = self.router.select_pool(&request.host, &request.path).to_string();

        match self.state.start_request(request.client_ip) {
            StateDecision::Allow { counted, .. } => {
                ctx.counted_concurrency = counted;
            }
            StateDecision::Reject { reason } => {
                ctx.decision = Decision::Reject {
                    status: 429,
                    body: "request throttled".to_string(),
                    reason,
                };
            }
            StateDecision::Sinkhole { reason } => {
                ctx.decision = Decision::Sinkhole { reason };
            }
            StateDecision::Blackhole { reason } => {
                ctx.decision = Decision::Blackhole { reason };
            }
        }

        if matches!(ctx.decision, Decision::Reject { .. } | Decision::Sinkhole { .. } | Decision::Blackhole { .. }) {
            return self.handle_decision(session, ctx, &request).await;
        }

        ctx.decision = self.engine.evaluate(&request);
        if matches!(ctx.decision, Decision::Reject { .. } | Decision::Sinkhole { .. } | Decision::Blackhole { .. }) {
            if matches!(ctx.decision, Decision::Reject { .. } | Decision::Blackhole { .. }) {
                let _ = self.state.record_infraction(request.client_ip, ctx.decision.reason());
            }
            return self.handle_decision(session, ctx, &request).await;
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Box<HttpPeer>> {
        let (cluster_name, cluster, load_balancer) = if ctx.decision.is_sinkhole() {
            let (cluster, lb) = self.cluster_for(&ctx.decision).map_err(Self::to_pingora_error)?;
            ("sinkhole", cluster, lb)
        } else {
            let (cluster, lb) = self
                .selected_cluster_for(ctx)
                .map_err(Self::to_pingora_error)?;
            (ctx.selected_pool.as_str(), cluster, lb)
        };
        let key = ctx
            .client_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let upstream = load_balancer.select(key.as_bytes(), 256).ok_or_else(|| {
            Self::to_pingora_error(anyhow!("no upstreams available in cluster {}", cluster.name))
        })?;

        info!(
            "routing client={} action={} cluster={} upstream={upstream:?}",
            key,
            ctx.decision.label(),
            cluster_name
        );

        Ok(Box::new(HttpPeer::new(
            upstream,
            cluster.use_tls,
            cluster.sni.clone(),
        )))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        let (cluster, _) = if ctx.decision.is_sinkhole() {
            self.cluster_for(&ctx.decision).map_err(Self::to_pingora_error)?
        } else {
            self.selected_cluster_for(ctx)
                .map_err(Self::to_pingora_error)?
        };
        if self.engine.strip_connection_headers() {
            let connection_tokens = upstream_request
                .headers
                .get("Connection")
                .and_then(|value| value.to_str().ok())
                .map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            for header in [
                "Connection",
                "Keep-Alive",
                "Proxy-Connection",
                "TE",
                "Trailer",
                "Transfer-Encoding",
                "Upgrade",
                "X-Forwarded-For",
                "X-Forwarded-Proto",
                "X-Forwarded-Host",
                "X-Forwarded-Port",
                "X-Real-IP",
                "True-Client-IP",
                "CF-Connecting-IP",
                "CF-Connecting-IPv6",
                "Forwarded",
            ] {
                upstream_request.remove_header(header);
            }
            for listed in connection_tokens {
                upstream_request.remove_header(listed.as_str());
            }
        }
        for header in &self.strip_inbound_internal_headers {
            upstream_request.remove_header(header.as_str());
        }
        upstream_request.insert_header("Host", cluster.host_header.as_str())?;
        if let Some(client_ip) = ctx.client_ip {
            upstream_request.insert_header("X-Backflow-Client-IP", client_ip.to_string())?;
            upstream_request.insert_header("X-Forwarded-For", client_ip.to_string())?;
        }
        upstream_request.insert_header("X-Forwarded-Host", ctx.host.as_str())?;
        upstream_request.insert_header("X-Forwarded-Proto", "http")?;
        if self.set_forwarded_port {
            upstream_request.insert_header("X-Forwarded-Port", "80")?;
        }
        upstream_request.insert_header("X-Backflow-Decision", ctx.decision.label())?;
        upstream_request.insert_header("X-Backflow-Pool", ctx.selected_pool.as_str())?;
        for (header, value) in &self.backend_headers {
            upstream_request.insert_header(header.as_str(), value.as_str())?;
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        upstream_response.insert_header("Server", self.server_header.as_str())?;
        upstream_response.insert_header("X-Backflow-Decision", ctx.decision.label())?;
        upstream_response.insert_header("X-Backflow-Reason", ctx.decision.reason())?;
        upstream_response.remove_header("alt-svc");
        Ok(())
    }

    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&pingora_core::Error>,
        ctx: &mut Self::CTX,
    ) {
        if ctx.counted_concurrency {
            if let Some(ip) = ctx.client_ip {
                self.state.finish_request(ip);
                ctx.counted_concurrency = false;
            }
        }

        let status = session
            .response_written()
            .map_or(0, |response| response.status.as_u16());

        match error {
            Some(error) => warn!(
                "request={} status={} action={} error={}",
                self.request_summary(session, ctx),
                status,
                ctx.decision.label(),
                error
            ),
            None => info!(
                "request={} status={} action={}",
                self.request_summary(session, ctx),
                status,
                ctx.decision.label()
            ),
        }
    }
}

impl BackflowProxy {
    async fn handle_decision(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        request: &RequestMeta,
    ) -> pingora_core::Result<bool> {
        match &ctx.decision {
            Decision::Allow | Decision::Sinkhole { .. } => Ok(false),
            Decision::Reject { status, body, reason } => {
                warn!(
                    "rejecting request from {} host={} reason={}",
                    request.client_ip, request.host, reason
                );
                session
                    .respond_error_with_body(*status, Bytes::from(body.clone()))
                    .await?;
                Ok(true)
            }
            Decision::Blackhole { reason } => {
                warn!(
                    "blackholing request from {} host={} reason={}",
                    request.client_ip, request.host, reason
                );
                session.shutdown().await;
                Ok(true)
            }
        }
    }
}
