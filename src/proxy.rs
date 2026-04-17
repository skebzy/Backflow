use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    net::IpAddr,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use http::Uri;
use ipnet::IpNet;
use log::{info, warn};
use pingora_core::{upstreams::peer::HttpPeer, Error};
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use tokio::time::sleep;

use crate::{
    config::{AppConfig, ClusterConfig, ProtectedPathConfig, TrafficAction},
    filters::{Decision, FilterEngine, RequestMeta},
    routing::Router,
    sinkhole::SharedLoadBalancer,
    state::{DefenseState, StateDecision},
};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

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
    forwarded_proto_header: String,
    preserve_trusted_proto_header: bool,
    set_forwarded_header: bool,
    trace_enabled: bool,
    request_id_header: String,
    trust_incoming_request_id: bool,
    inject_correlation_header: bool,
    response_headers: HashMap<String, String>,
    remove_response_headers: Vec<String>,
    sinkhole: SinkholeRuntime,
    blackhole: BlackholeRuntime,
    maintenance: MaintenanceRuntime,
    internal_endpoints: InternalEndpointsRuntime,
    protected_paths: Vec<ProtectedPathRuntime>,
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
            forwarded_proto_header: config.backend.forwarded_proto_header.clone(),
            preserve_trusted_proto_header: config.backend.preserve_trusted_proto_header,
            set_forwarded_header: config.backend.set_forwarded_header,
            trace_enabled: config.trace.enabled,
            request_id_header: config.trace.request_id_header.clone(),
            trust_incoming_request_id: config.trace.trust_incoming_request_id,
            inject_correlation_header: config.trace.inject_correlation_header,
            response_headers: config.response.headers.clone(),
            remove_response_headers: config.response.remove_headers.clone(),
            sinkhole: SinkholeRuntime::from_config(&config.sinkhole),
            blackhole: BlackholeRuntime::from_config(&config.blackhole),
            maintenance: MaintenanceRuntime::from_config(&config.maintenance),
            internal_endpoints: InternalEndpointsRuntime::from_config(&config.internal_endpoints),
            protected_paths: config
                .protected_paths
                .iter()
                .map(ProtectedPathRuntime::from_config)
                .collect(),
        }
    }

    fn request_meta(session: &Session) -> Result<RequestMeta> {
        let peer_ip = Self::session_peer_ip(session)
            .ok_or_else(|| anyhow!("failed to read client address from session"))?;
        let req = session.req_header();
        let path = req.uri.path().to_string();
        let query = req.uri.query().unwrap_or_default().to_string();
        let query_len = query.len();
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
        let content_length_values = req.headers.get_all("Content-Length");
        let content_length_header_count = content_length_values.iter().count();
        let mut has_invalid_content_length = false;
        let mut content_length = 0u64;
        for value in content_length_values.iter() {
            match value
                .to_str()
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
            {
                Some(parsed) => {
                    content_length = parsed;
                }
                None => {
                    has_invalid_content_length = true;
                    break;
                }
            }
        }
        let transfer_encoding_values = req.headers.get_all("Transfer-Encoding");
        let transfer_encoding_header_count = transfer_encoding_values.iter().count();
        let transfer_encoding_tokens = transfer_encoding_values
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let has_transfer_encoding = !transfer_encoding_tokens.is_empty();
        let has_non_chunked_transfer_encoding = transfer_encoding_tokens
            .iter()
            .any(|value| value != "chunked");
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
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | ':'));
        let has_valid_path = path.starts_with('/');
        let has_malformed_encoding = crate::filters::has_malformed_percent_encoding(&path)
            || crate::filters::has_malformed_percent_encoding(&query);
        let has_path_traversal =
            crate::filters::has_path_traversal(&path) || crate::filters::has_path_traversal(&query);
        let path_segment_count = crate::filters::count_path_segments(&path);
        let query_param_count = crate::filters::count_query_params(&query);

        Ok(RequestMeta {
            client_ip: peer_ip,
            method,
            path,
            query,
            query_len,
            user_agent,
            host,
            header_count,
            header_bytes,
            content_length,
            content_length_header_count,
            has_invalid_content_length,
            empty_headers,
            host_header_count,
            transfer_encoding_header_count,
            has_non_chunked_transfer_encoding,
            has_underscored_headers,
            header_names,
            has_conflicting_content_headers: has_transfer_encoding && content_length > 0,
            has_valid_host,
            has_valid_path,
            path_segment_count,
            query_param_count,
            has_path_traversal,
            has_malformed_encoding,
        })
    }

    fn cluster_for<'a>(
        &'a self,
        decision: &Decision,
    ) -> Result<(&'a ClusterConfig, &'a SharedLoadBalancer)> {
        if decision.is_sinkhole() {
            if !self.sinkhole_uses_upstream() {
                return Err(anyhow!(
                    "sinkhole decision reached but sinkhole mode is local, not proxy"
                ));
            }
            let cluster = self.sinkhole_cluster.as_ref().ok_or_else(|| {
                anyhow!("sinkhole decision reached but sinkhole cluster is missing")
            })?;
            let lb = self.sinkhole_lb.as_ref().ok_or_else(|| {
                anyhow!("sinkhole decision reached but sinkhole load balancer is missing")
            })?;
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
        Error::because(
            pingora_core::ErrorType::InternalError,
            "backflow error",
            error,
        )
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

    fn session_peer_ip(session: &Session) -> Option<IpAddr> {
        session
            .client_addr()
            .and_then(|addr| addr.as_inet().map(|addr| addr.ip()))
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

    fn current_request_id(&self, session: &Session) -> Option<String> {
        if !self.trace_enabled {
            return None;
        }

        if self.trust_incoming_request_id {
            if let Some(value) = session
                .req_header()
                .headers
                .get(self.request_id_header.as_str())
            {
                if let Ok(value) = value.to_str() {
                    let value = value.trim();
                    if is_valid_request_id(value) {
                        return Some(value.to_string());
                    }
                }
            }
        }

        Some(Self::generate_request_id(
            session
                .client_addr()
                .and_then(|addr| addr.as_inet().map(|addr| addr.ip())),
        ))
    }

    fn generate_request_id(client_ip: Option<IpAddr>) -> String {
        let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis() as u64);
        let mut hasher = DefaultHasher::new();
        client_ip.hash(&mut hasher);
        counter.hash(&mut hasher);
        millis.hash(&mut hasher);
        format!("{millis:016x}{counter:08x}{:016x}", hasher.finish())
    }

    fn is_ready(&self) -> bool {
        self.pools
            .get(&self.default_pool)
            .and_then(|pool| pool.select(b"readyz", 256))
            .is_some()
    }

    fn forwarded_proto(&self, session: &Session) -> &'static str {
        let peer_ip = Self::session_peer_ip(session);
        let trusted_peer = peer_ip
            .map(|ip| {
                self.trusted_proxies
                    .iter()
                    .any(|network| network.contains(&ip))
            })
            .unwrap_or(false);

        if self.preserve_trusted_proto_header && trusted_peer {
            if let Some(value) = session
                .req_header()
                .headers
                .get(self.forwarded_proto_header.as_str())
                .and_then(|value| value.to_str().ok())
            {
                let normalized = value.trim().to_ascii_lowercase();
                if normalized == "https" {
                    return "https";
                }
            }
        }

        "http"
    }

    fn request_summary(&self, session: &Session, ctx: &RequestContext) -> String {
        let method = session.req_header().method.as_str();
        let path = if ctx.upstream_path.is_empty() {
            session.req_header().uri.path().to_string()
        } else {
            ctx.upstream_path.clone()
        };
        let host = if ctx.host.is_empty() {
            session
                .req_header()
                .headers
                .get("Host")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("-")
                .to_string()
        } else {
            ctx.host.clone()
        };
        let client = ctx
            .client_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "-".to_string());

        format!("{client} {method} {host}{path}")
    }

    fn is_protocol_upgrade(request: &pingora_http::RequestHeader) -> bool {
        let has_upgrade = request.headers.get("Upgrade").is_some();
        let connection_upgrade = request
            .headers
            .get("Connection")
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
            .unwrap_or(false);

        has_upgrade || connection_upgrade
    }

    fn forwarded_header_value(
        &self,
        ctx: &RequestContext,
        forwarded_proto: &str,
    ) -> Option<String> {
        let client_ip = ctx.client_ip?;
        let client = match client_ip {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("\"[{ip}]\""),
        };
        let host = if ctx.host.is_empty() {
            String::new()
        } else {
            format!(";host=\"{}\"", ctx.host)
        };

        Some(format!("for={client};proto={forwarded_proto}{host}"))
    }

    fn sinkhole_uses_upstream(&self) -> bool {
        self.sinkhole.enabled && matches!(self.sinkhole.mode, crate::config::SinkholeMode::Proxy)
    }

    fn tarpit_duration(
        &self,
        base_ms: u64,
        jitter_ms: u64,
        ctx: &RequestContext,
        salt: &str,
    ) -> Duration {
        let mut total = base_ms;
        if jitter_ms > 0 {
            let mut hasher = DefaultHasher::new();
            salt.hash(&mut hasher);
            ctx.client_ip.hash(&mut hasher);
            ctx.request_id.hash(&mut hasher);
            ctx.path.hash(&mut hasher);
            total += hasher.finish() % (jitter_ms + 1);
        }

        Duration::from_millis(total)
    }

    async fn maybe_handle_internal_endpoint(
        &self,
        session: &mut Session,
        request: &RequestMeta,
        ctx: &mut RequestContext,
    ) -> pingora_core::Result<bool> {
        if !self.internal_endpoints.enabled {
            return Ok(false);
        }

        if request.path == self.internal_endpoints.health_path {
            ctx.decision = Decision::allow();
            session
                .respond_error_with_body(200, Bytes::from_static(b"{\"status\":\"ok\"}"))
                .await?;
            return Ok(true);
        }

        if request.path == self.internal_endpoints.ready_path {
            ctx.decision = Decision::allow();
            let status = if self.is_ready() { 200 } else { 503 };
            let body = if status == 200 {
                Bytes::from_static(b"{\"status\":\"ready\"}")
            } else {
                Bytes::from_static(b"{\"status\":\"degraded\"}")
            };
            session.respond_error_with_body(status, body).await?;
            return Ok(true);
        }

        Ok(false)
    }

    fn maintenance_decision(&self, request: &RequestMeta) -> Option<Decision> {
        if !self.maintenance.enabled {
            return None;
        }

        if self
            .maintenance
            .allow_path_prefixes
            .iter()
            .any(|prefix| request.path.starts_with(prefix))
        {
            return None;
        }

        if self
            .maintenance
            .allow_ips
            .iter()
            .any(|network| network.contains(&request.client_ip))
        {
            return None;
        }

        Some(Decision::Reject {
            status: self.maintenance.status,
            body: self.maintenance.body.clone(),
            reason: "maintenance mode enabled".to_string(),
        })
    }

    fn protected_path_decision(&self, request: &RequestMeta) -> Option<Decision> {
        for rule in &self.protected_paths {
            if !request.path.starts_with(&rule.path_prefix) {
                continue;
            }

            if rule
                .allow_ips
                .iter()
                .any(|network| network.contains(&request.client_ip))
            {
                return None;
            }

            return Some(match rule.action {
                TrafficAction::Reject => Decision::Reject {
                    status: rule.reject_status,
                    body: rule.reject_body.clone(),
                    reason: format!("protected path {} denied", rule.path_prefix),
                },
                TrafficAction::Sinkhole => Decision::Sinkhole {
                    reason: format!("protected path {} denied", rule.path_prefix),
                },
                TrafficAction::Blackhole => Decision::Blackhole {
                    reason: format!("protected path {} denied", rule.path_prefix),
                },
            });
        }

        None
    }
}

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub client_ip: Option<IpAddr>,
    pub host: String,
    pub path: String,
    pub upstream_path: String,
    pub matched_path_prefix: Option<String>,
    pub decision: Decision,
    pub counted_concurrency: bool,
    pub selected_pool: String,
    pub request_id: Option<String>,
}

#[async_trait]
impl ProxyHttp for BackflowProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext {
            client_ip: None,
            host: String::new(),
            path: String::new(),
            upstream_path: String::new(),
            matched_path_prefix: None,
            decision: Decision::allow(),
            counted_concurrency: false,
            selected_pool: String::new(),
            request_id: None,
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
        let route = self.router.select(&request.host, &request.path);
        ctx.selected_pool = route.target_pool.to_string();
        ctx.upstream_path = route.upstream_path;
        ctx.matched_path_prefix = route.matched_path_prefix.map(str::to_string);
        ctx.request_id = self.current_request_id(session);

        if self
            .maybe_handle_internal_endpoint(session, &request, ctx)
            .await?
        {
            return Ok(true);
        }

        if let Some(decision) = self.maintenance_decision(&request) {
            ctx.decision = decision;
            return self.handle_decision(session, ctx, &request).await;
        }

        if let Some(decision) = self.protected_path_decision(&request) {
            ctx.decision = decision;
            if matches!(
                ctx.decision,
                Decision::Reject { .. } | Decision::Blackhole { .. }
            ) {
                let _ = self
                    .state
                    .record_infraction(request.client_ip, ctx.decision.reason());
            }
            return self.handle_decision(session, ctx, &request).await;
        }

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

        if matches!(
            ctx.decision,
            Decision::Reject { .. } | Decision::Sinkhole { .. } | Decision::Blackhole { .. }
        ) {
            return self.handle_decision(session, ctx, &request).await;
        }

        ctx.decision = self.engine.evaluate(&request);
        if matches!(
            ctx.decision,
            Decision::Reject { .. } | Decision::Sinkhole { .. } | Decision::Blackhole { .. }
        ) {
            if matches!(
                ctx.decision,
                Decision::Reject { .. } | Decision::Blackhole { .. }
            ) {
                let _ = self
                    .state
                    .record_infraction(request.client_ip, ctx.decision.reason());
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
            let (cluster, lb) = self
                .cluster_for(&ctx.decision)
                .map_err(Self::to_pingora_error)?;
            (self.sinkhole.log_label.as_str(), cluster, lb)
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
            Self::to_pingora_error(anyhow!(
                "no upstreams available in cluster {}",
                cluster.name
            ))
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
            self.cluster_for(&ctx.decision)
                .map_err(Self::to_pingora_error)?
        } else {
            self.selected_cluster_for(ctx)
                .map_err(Self::to_pingora_error)?
        };
        let is_upgrade = Self::is_protocol_upgrade(upstream_request);
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
                "Keep-Alive",
                "Proxy-Connection",
                "TE",
                "Trailer",
                "Transfer-Encoding",
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
            if !is_upgrade {
                upstream_request.remove_header("Connection");
                upstream_request.remove_header("Upgrade");
            }
            for listed in connection_tokens {
                if is_upgrade && listed.eq_ignore_ascii_case("upgrade") {
                    continue;
                }
                upstream_request.remove_header(listed.as_str());
            }
        }
        for header in &self.strip_inbound_internal_headers {
            upstream_request.remove_header(header.as_str());
        }
        let host_header = if cluster.preserve_original_host && !ctx.host.is_empty() {
            ctx.host.as_str()
        } else {
            cluster.host_header.as_str()
        };
        upstream_request.insert_header("Host", host_header)?;
        if !ctx.upstream_path.is_empty() && ctx.upstream_path != ctx.path {
            let query = upstream_request.uri.query().unwrap_or_default();
            let path_and_query = if query.is_empty() {
                ctx.upstream_path.clone()
            } else {
                format!("{}?{query}", ctx.upstream_path)
            };
            let rewritten_uri = Uri::builder()
                .path_and_query(path_and_query.as_str())
                .build()
                .map_err(|error| {
                    Self::to_pingora_error(anyhow!("invalid rewritten uri: {error}"))
                })?;
            upstream_request.set_uri(rewritten_uri);
        }
        if let Some(client_ip) = ctx.client_ip {
            upstream_request.insert_header("X-Backflow-Client-IP", client_ip.to_string())?;
            upstream_request.insert_header("X-Forwarded-For", client_ip.to_string())?;
        }
        let forwarded_proto = self.forwarded_proto(_session);
        upstream_request.insert_header("X-Forwarded-Host", ctx.host.as_str())?;
        upstream_request.insert_header("X-Forwarded-Proto", forwarded_proto)?;
        if self.set_forwarded_port {
            let port = if forwarded_proto == "https" {
                "443"
            } else {
                "80"
            };
            upstream_request.insert_header("X-Forwarded-Port", port)?;
        }
        if let Some(prefix) = &ctx.matched_path_prefix {
            upstream_request.insert_header("X-Forwarded-Prefix", prefix.as_str())?;
        }
        if self.set_forwarded_header {
            if let Some(value) = self.forwarded_header_value(ctx, forwarded_proto) {
                upstream_request.insert_header("Forwarded", value)?;
            }
        }
        upstream_request.insert_header("X-Backflow-Decision", ctx.decision.label())?;
        upstream_request.insert_header("X-Backflow-Pool", ctx.selected_pool.as_str())?;
        if let Some(request_id) = &ctx.request_id {
            upstream_request.insert_header(self.request_id_header.as_str(), request_id.as_str())?;
            if self.inject_correlation_header {
                upstream_request.insert_header("X-Correlation-ID", request_id.as_str())?;
            }
        }
        for (header, value) in &self.backend_headers {
            upstream_request.insert_header(header.clone(), value.clone())?;
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
        if let Some(request_id) = &ctx.request_id {
            upstream_response
                .insert_header(self.request_id_header.as_str(), request_id.as_str())?;
        }
        for (header, value) in &self.response_headers {
            upstream_response.insert_header(header.as_str(), value.as_str())?;
        }
        for header in &self.remove_response_headers {
            upstream_response.remove_header(header.as_str());
        }
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
            Decision::Allow => Ok(false),
            Decision::Sinkhole { reason } => {
                if self.sinkhole_uses_upstream() {
                    return Ok(false);
                }

                let tarpit = self.tarpit_duration(
                    self.sinkhole.delay_ms,
                    self.sinkhole.jitter_ms,
                    ctx,
                    "sinkhole",
                );
                if !tarpit.is_zero() {
                    sleep(tarpit).await;
                }

                warn!(
                    "sinkholing request from {} host={} reason={} mode=local",
                    request.client_ip, request.host, reason
                );
                let mut response =
                    ResponseHeader::build(self.sinkhole.status, None).map_err(|error| {
                        Self::to_pingora_error(anyhow!("sinkhole response build failed: {error}"))
                    })?;
                response.insert_header("Content-Type", self.sinkhole.content_type.as_str())?;
                response.insert_header("Cache-Control", "no-store, no-cache, must-revalidate")?;
                response.insert_header("Pragma", "no-cache")?;
                response.insert_header("X-Backflow-Decision", ctx.decision.label())?;
                response.insert_header("X-Backflow-Reason", ctx.decision.reason())?;
                for (header, value) in &self.sinkhole.headers {
                    response.insert_header(header.as_str(), value.as_str())?;
                }
                if let Some(request_id) = &ctx.request_id {
                    response.insert_header(self.request_id_header.as_str(), request_id.as_str())?;
                }
                session.write_response_header(Box::new(response)).await?;
                session
                    .write_response_body(Bytes::from(self.sinkhole.body.clone()), true)
                    .await?;
                Ok(true)
            }
            Decision::Reject {
                status,
                body,
                reason,
            } => {
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
                let tarpit = self.tarpit_duration(
                    self.blackhole.delay_ms,
                    self.blackhole.jitter_ms,
                    ctx,
                    "blackhole",
                );
                if self.blackhole.log {
                    warn!(
                        "blackholing request from {} host={} reason={} delay_ms={}",
                        request.client_ip,
                        request.host,
                        reason,
                        tarpit.as_millis()
                    );
                }
                if !tarpit.is_zero() {
                    sleep(tarpit).await;
                }
                session.shutdown().await;
                Ok(true)
            }
        }
    }
}

fn is_valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '/'))
}

struct MaintenanceRuntime {
    enabled: bool,
    status: u16,
    body: String,
    allow_ips: Vec<IpNet>,
    allow_path_prefixes: Vec<String>,
}

impl MaintenanceRuntime {
    fn from_config(config: &crate::config::MaintenanceConfig) -> Self {
        Self {
            enabled: config.enabled,
            status: config.status,
            body: config.body.clone(),
            allow_ips: crate::filters::parse_ip_rules(&config.allow_ips),
            allow_path_prefixes: config.allow_path_prefixes.clone(),
        }
    }
}

struct SinkholeRuntime {
    enabled: bool,
    mode: crate::config::SinkholeMode,
    status: u16,
    body: String,
    content_type: String,
    headers: HashMap<String, String>,
    delay_ms: u64,
    jitter_ms: u64,
    log_label: String,
}

impl SinkholeRuntime {
    fn from_config(config: &crate::config::SinkholeConfig) -> Self {
        Self {
            enabled: config.enabled,
            mode: config.mode.clone(),
            status: config.local_status,
            body: config.local_body.clone(),
            content_type: config.local_content_type.clone(),
            headers: config.local_headers.clone(),
            delay_ms: config.delay_ms,
            jitter_ms: config.jitter_ms,
            log_label: match config.mode {
                crate::config::SinkholeMode::Proxy => "sinkhole-proxy".to_string(),
                crate::config::SinkholeMode::Local => "sinkhole-local".to_string(),
            },
        }
    }
}

struct BlackholeRuntime {
    delay_ms: u64,
    jitter_ms: u64,
    log: bool,
}

impl BlackholeRuntime {
    fn from_config(config: &crate::config::BlackholeConfig) -> Self {
        Self {
            delay_ms: config.delay_ms,
            jitter_ms: config.jitter_ms,
            log: config.log,
        }
    }
}

struct InternalEndpointsRuntime {
    enabled: bool,
    health_path: String,
    ready_path: String,
}

impl InternalEndpointsRuntime {
    fn from_config(config: &crate::config::InternalEndpointsConfig) -> Self {
        Self {
            enabled: config.enabled,
            health_path: config.health_path.clone(),
            ready_path: config.ready_path.clone(),
        }
    }
}

struct ProtectedPathRuntime {
    path_prefix: String,
    allow_ips: Vec<IpNet>,
    action: TrafficAction,
    reject_status: u16,
    reject_body: String,
}

impl ProtectedPathRuntime {
    fn from_config(config: &ProtectedPathConfig) -> Self {
        Self {
            path_prefix: config.path_prefix.clone(),
            allow_ips: crate::filters::parse_ip_rules(&config.allow_ips),
            action: config.action,
            reject_status: config.reject_status,
            reject_body: config.reject_body.clone(),
        }
    }
}
