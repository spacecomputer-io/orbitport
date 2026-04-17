use serde::Deserialize;
use std::sync::Arc;
use tokio::time::{Duration, Instant, timeout};
use warp::{Filter, Rejection, Reply, reject::Reject};

use crate::metrics;
use crate::service_manager::ServiceManager;
use crate::types::{EncryptionKey, GatewayError, ServiceRequest};

use crate::filters::{AuthContext, RateLimiter, with_auth, with_rate_limiter};
use crate::plugins::PluginCatalog;
use crate::services::jrpc::{JsonRpcRequest, JsonRpcResponse};
use crate::trng::SRC_DERIVED_TRNG;

impl Reject for GatewayError {}

#[derive(Debug, Clone, Deserialize)]
struct QueryParams {
    /// The source of the service, i.e. the service provider
    src: Option<String>,
    /// The number of derived items to return (EXPERIMENTAL)
    bulk: Option<usize>,
    /// The key for encryption in the format of <scheme>@<key> (EXPERIMENTAL)
    /// This is used to encrypt the service result.
    /// Currently only supports tpk (threshold public key) i.e. "tpk@<key>".
    key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PostBody {
    /// The source of the service, i.e. the service provider
    src: Option<String>,
    /// The number of derived items to return
    bulk: Option<usize>,
    /// The key for encryption in the format of <scheme>@<key> (EXPERIMENTAL)
    /// This is used to encrypt the service result.
    /// Currently only supports tpk (threshold public key) i.e. "tpk@<key>".
    key: Option<String>,
    /// The arguments for the service
    /// in a vector of [(key, value), ...]
    args: Option<Vec<(String, String)>>,
}

/// Starts the gateway server, returns a future that resolves when the server stops or fails
/// It exposes the following enpoints:
pub async fn start(
    http_port: u16,
    service_manager: Arc<ServiceManager>,
    plugin_catalog: Arc<PluginCatalog>,
    limit: u32,
    limit_window: u64,
    bulk_max: usize,
) {
    let service_manager_clone = service_manager.clone();
    let service_manager_post_clone = service_manager.clone();

    let rate_limiter = Arc::new(RateLimiter::new(limit, Duration::from_secs(limit_window))); // 100 requests per minute

    let rpc_route = warp::post()
        .and(warp::path("api").and(warp::path("v1").and(warp::path("rpc"))))
        .and(with_rate_limiter(
            with_auth(service_manager.get_auth_client()),
            rate_limiter.clone(),
        ))
        .and(warp::body::content_length_limit(1024))
        .and(warp::body::json())
        .and(warp::any().map(move || plugin_catalog.clone()))
        .and_then(handle_rpc);

    let bulk_max_get = bulk_max;
    let get_route = warp::path!("api" / "v1" / "services" / String)
        .and(warp::get())
        .and(with_rate_limiter(
            with_auth(service_manager.get_auth_client()),
            rate_limiter.clone(),
        ))
        .and(warp::query::<QueryParams>())
        .and(warp::any().map(move || service_manager_clone.clone()))
        .and(warp::any().map(move || bulk_max_get))
        .and_then(handle_get);

    let bulk_max_post = bulk_max;
    let post_route = warp::path!("api" / "v1" / "services" / String)
        .and(warp::post())
        .and(with_rate_limiter(
            with_auth(service_manager.get_auth_client()),
            rate_limiter.clone(),
        ))
        .and(warp::body::content_length_limit(1024)) // limit to 1 KB payload
        .and(warp::body::json())
        .and(warp::query::<QueryParams>())
        .and(warp::any().map(move || service_manager_post_clone.clone()))
        .and(warp::any().map(move || bulk_max_post))
        .and_then(handle_post);

    let health_route = warp::path("healthz").map(|| {
        warp::reply::json(&serde_json::json!({
            "status": "ok"
        }))
    });

    let routes = get_route
        .or(post_route)
        .or(rpc_route)
        .or(health_route.with(warp::log("health_check")));

    tracing::info!("Starting http server on: 0.0.0.0:{}", http_port);

    warp::serve(routes).run(([0, 0, 0, 0], http_port)).await;
}

async fn handle_rpc(
    auth: AuthContext,
    body: JsonRpcRequest,
    plugin_catalog: Arc<PluginCatalog>,
) -> Result<impl Reply, Rejection> {
    tracing::debug!("Handling RPC request [id={}] {:?}", body.id, body);
    let req_id = body.id;
    let rpc_call = body.call;
    if let Err(e) = rpc_call.validate() {
        tracing::error!("RPC validation error [id={}]: {}", req_id, e);
        let res: JsonRpcResponse<()> =
            JsonRpcResponse::error(req_id, -32602, format!("Invalid request: {}", e));
        return Ok(warp::reply::json(&res));
    }
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
    let client_id = auth.client_id;

    match timeout(
        REQUEST_TIMEOUT,
        rpc_call.execute(req_id, &client_id, &plugin_catalog),
    )
    .await
    {
        Ok(Ok(result)) => {
            tracing::debug!("RPC executed successfully [id={}]", req_id);
            Ok(warp::reply::json(&result))
        }
        Ok(Err(e)) => {
            tracing::warn!("RPC execution error [id={}]: {}", req_id, e);

            let res: JsonRpcResponse<()> = JsonRpcResponse::error(req_id, -32001, e.to_string());

            Ok(warp::reply::json(&res))
        }
        Err(_) => {
            tracing::error!("RPC request timed out [id={}]", req_id);

            let res: JsonRpcResponse<()> =
                JsonRpcResponse::error(req_id, -32002, "Request timed out");

            Ok(warp::reply::json(&res))
        }
    }
}

async fn handle_get(
    service: String,
    _auth: AuthContext,
    query: QueryParams,
    service_manager: Arc<ServiceManager>,
    bulk_max: usize,
) -> Result<impl Reply, Rejection> {
    let req_id = new_req_id();
    tracing::debug!(
        "[req={}] Handling GET request for service: {}",
        req_id,
        service
    );
    let src = if let Some(s) = query.src {
        vec![s.clone()]
    } else {
        vec![SRC_DERIVED_TRNG.to_string()]
    };
    if let Some(b) = query.bulk {
        if b > bulk_max {
            metrics::record_validation("GET", "bulk_limit_exceeded");
            return Err(warp::reject::custom(GatewayError::BadRequest(format!(
                "Bulk size {} exceeds maximum {}",
                b, bulk_max
            ))));
        } else {
            tracing::debug!("[req={}] Bulk size: {}", req_id, b);
        }
    }
    let enc_key = if let Some(key) = query.key {
        Some(EncryptionKey::new_from_arg(&key).map_err(|e| {
            metrics::record_validation("GET", "invalid_encryption_key");
            warp::reject::custom(GatewayError::BadRequest(e.to_string()))
        })?)
    } else {
        None
    };
    let svc_req = ServiceRequest {
        req_id,
        service,
        src,
        bulk: query.bulk,
        enc_key,
        args: None,
    };
    handle_service_req(svc_req, service_manager.clone()).await
}

async fn handle_post(
    service: String,
    _auth: AuthContext,
    body: PostBody,
    query: QueryParams,
    service_manager: Arc<ServiceManager>,
    bulk_max: usize,
) -> Result<impl Reply, Rejection> {
    let req_id = new_req_id();
    let src = if let Some(s) = body.src {
        s.clone()
    } else {
        query.src.unwrap_or(SRC_DERIVED_TRNG.to_string()).clone()
    };

    let bulk = if let Some(b) = body.bulk {
        Some(b)
    } else {
        query.bulk
    };
    if let Some(b) = bulk {
        if b > bulk_max {
            metrics::record_validation("POST", "bulk_limit_exceeded");
            return Err(warp::reject::custom(GatewayError::BadRequest(format!(
                "Bulk size {} exceeds maximum {}",
                b, bulk_max
            ))));
        } else {
            tracing::debug!("[req={}] Bulk size: {}", req_id, b);
        }
    }
    let key = if let Some(k) = query.key {
        Some(k)
    } else {
        body.key
    };
    let enc_key = if let Some(key) = key {
        Some(EncryptionKey::new_from_arg(&key).map_err(|e| {
            metrics::record_validation("POST", "invalid_encryption_key");
            warp::reject::custom(GatewayError::BadRequest(e.to_string()))
        })?)
    } else {
        None
    };
    let args = body.args.clone();
    let svc_req = ServiceRequest {
        req_id,
        service,
        src: vec![src],
        bulk,
        enc_key,
        args,
    };
    handle_service_req(svc_req, service_manager.clone()).await
}

async fn handle_service_req(
    svc_req: ServiceRequest,
    service_manager: Arc<ServiceManager>,
) -> Result<impl Reply, Rejection> {
    let timer: Instant = Instant::now();

    let req_id = svc_req.req_id;
    let svc_name = svc_req.service.clone();
    metrics::API_REQ_COUNTER
        .with_label_values(&[&svc_name])
        .inc();
    let response = timeout(Duration::from_secs(10), async {
        service_manager.handle(svc_req).await
    })
    .await;

    let duration = timer.elapsed().as_secs_f64();
    metrics::API_REQ_DURATION_SECONDS
        .with_label_values(&[&svc_name])
        .observe(duration);

    match response {
        Ok(Ok(res)) => match res.result {
            Ok(result) => {
                metrics::API_REQ_OK_COUNTER
                    .with_label_values(&[&svc_name])
                    .inc();
                metrics::record_request(&svc_name, "ok", duration);
                tracing::debug!("[req={}] Got service result", req_id);
                Ok(warp::reply::json(&result))
            }
            Err(e) => {
                metrics::API_REQ_ERR_COUNTER
                    .with_label_values(&[&svc_name])
                    .inc();
                metrics::record_request(&svc_name, "service_error", duration);
                tracing::error!("[req={}] Error result: {:?}", req_id, e);
                Err(warp::reject::custom(e))
            }
        },
        Ok(Err(e)) => {
            metrics::API_REQ_FAILED_COUNTER
                .with_label_values(&[&svc_name])
                .inc();
            metrics::record_request(&svc_name, "routing_error", duration);
            tracing::error!("[req={}] Error routing request: {:?}", req_id, e);
            Err(warp::reject::custom(e))
        }
        Err(_) => {
            metrics::API_REQ_TIMEOUT_COUNTER
                .with_label_values(&[&svc_name])
                .inc();
            metrics::record_request(&svc_name, "timeout", duration);
            tracing::error!("[req={}] Request timed out", req_id);
            Err(warp::reject::custom(GatewayError::ServiceTimeout))
        }
    }
}

/// Generates a new random request ID.
fn new_req_id() -> u64 {
    use rand::Rng;
    let mut rng = rand::rng();
    rng.random_range(1..u64::MAX)
}
