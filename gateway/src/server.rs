use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, convert::Infallible, sync::Arc};
use thiserror::Error;
use tokio::{
    sync::Mutex,
    time::{Duration, Instant, timeout},
};
use tonic::transport::Channel;
use warp::{
    Filter, Rejection, Reply,
    filters::header::headers_cloned,
    http::header::{AUTHORIZATION, HeaderMap, HeaderValue},
    reject::Reject,
};

use crate::metrics;
use crate::proto::auth::{
    TokenValidationRequest, TokenValidationResponse, auth_agent_client::AuthAgentClient,
};
use crate::service::{ServiceError, ServiceRequest};
use crate::service_manager::ServiceManager;
use crate::trng::{SRC_APTOS_ORBITAL, SRC_DERIVED_TRNG};

#[derive(Error, Debug)]
pub enum GatewayError {
    #[error("Missing Authorization header")]
    NoAuthHeaderError,
    #[error("Invalid Authorization header")]
    InvalidAuthHeaderError,
    #[error("Failed to connect to auth agent: {0}")]
    AuthAgentConnectionError(String),
    #[error("Failed to authenticate")]
    AuthenticationFailed,
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
}

impl Reject for GatewayError {}

impl Reject for ServiceError {}

const BEARER: &str = "Bearer ";

/// Rate limit structure
pub type RateLimit = (u32, Instant);
/// Rate limit items
type RateLimiterItems = Arc<Mutex<HashMap<String, RateLimit>>>;
/// Rate limiter
pub struct RateLimiter {
    items: RateLimiterItems,
    max_requests: u32,
    time_window: Duration,
}

impl RateLimiter {
    fn new(max_requests: u32, time_window: Duration) -> Self {
        RateLimiter {
            items: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            time_window,
        }
    }
}

pub fn with_auth(
    service_manager: Arc<ServiceManager>,
) -> impl Filter<Extract = (String,), Error = warp::Rejection> + Clone {
    let auth_client = service_manager.get_auth_client();
    headers_cloned()
        .map(move |headers: HeaderMap<HeaderValue>| (headers, auth_client.clone()))
        .and_then(authorize)
}

type ApiResult<T> = std::result::Result<T, warp::Rejection>;

async fn authorize(
    (headers, mut auth_client): (HeaderMap<HeaderValue>, AuthAgentClient<Channel>),
) -> ApiResult<String> {
    match jwt_from_header(&headers) {
        Ok(jwt) => {
            let request = tonic::Request::new(TokenValidationRequest { token: jwt.clone() });
            let response: TokenValidationResponse = auth_client
                .validate_token(request)
                .await
                .map_err(|e| match e.code() {
                    tonic::Code::Unavailable | tonic::Code::NotFound => {
                        tracing::error!("Auth agent is unavailable: {}", e);
                        warp::reject::custom(GatewayError::AuthAgentConnectionError(
                            "unavailable".to_string(),
                        ))
                    }
                    _ => {
                        tracing::error!("Failed to authorize JWT: {}", e);
                        warp::reject::custom(GatewayError::AuthenticationFailed)
                    }
                })?
                .into_inner();
            if !response.ok {
                return Err(warp::reject::custom(GatewayError::AuthenticationFailed));
            }
            tracing::debug!("JWT authorized successfully");
            Ok(jwt)
        }
        Err(e) => Err(warp::reject::custom(e)),
    }
}

fn jwt_from_header(headers: &HeaderMap<HeaderValue>) -> Result<String, GatewayError> {
    let header = match headers.get(AUTHORIZATION) {
        Some(v) => v,
        None => return Err(GatewayError::NoAuthHeaderError),
    };
    let auth_header = match std::str::from_utf8(header.as_bytes()) {
        Ok(v) => v,
        Err(_) => return Err(GatewayError::NoAuthHeaderError),
    };
    extract_jwt(auth_header)
}

fn extract_jwt(auth_header: &str) -> Result<String, GatewayError> {
    if !auth_header.starts_with(BEARER) {
        return Err(GatewayError::InvalidAuthHeaderError);
    }
    Ok(auth_header.trim_start_matches(BEARER).to_owned())
}

// Create a rate limiter filter
pub fn with_rate_limiter(
    rate_limiter: Arc<RateLimiter>,
) -> impl Filter<Extract = ((),), Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::header::optional::<String>(AUTHORIZATION.as_str()))
        .and(warp::any().map(move || rate_limiter.clone()))
        .and_then(rate_limit)
}

/// Rate limiting logic.
async fn rate_limit(
    auth_header: Option<String>,
    rate_limiter: Arc<RateLimiter>,
) -> Result<(), warp::Rejection> {
    // NOTE: Using empty_token in case authentication is off, in case authentication was on and there is no auth header
    // this will be rejected before this point.
    let empty_token = format!("{}empty", BEARER);
    let token = extract_jwt(auth_header.as_deref().unwrap_or(empty_token.as_str()))
        .map_err(|_| warp::reject::custom(GatewayError::NoAuthHeaderError))?;
    // Hash the token to avoid storing it directly
    let mut hasher = Sha256::new();
    hasher.update(token);
    let token_hash = format!("{:x}", hasher.finalize());

    let mut items = rate_limiter.items.lock().await;

    // Check the current time and rate limit
    let now = Instant::now();
    let entry = items.entry(token_hash).or_insert((0, now));

    // Reset the count if the time window has passed
    if now.duration_since(entry.1) > rate_limiter.time_window {
        entry.0 = 0;
        entry.1 = now;
    }
    entry.0 += 1;

    // Check if the request count exceeds the limit
    if entry.0 > rate_limiter.max_requests {
        return Err(warp::reject::custom(GatewayError::RateLimitExceeded)); // Use a custom rejection
    }

    Ok(())
}

/// Metrics endpoint handler, gathers metrics from the prometheus registry
async fn metrics_handler() -> Result<impl Reply, Infallible> {
    use prometheus::{Encoder, TextEncoder};
    let encoder = TextEncoder::new();

    let mut buffer = Vec::new();
    let metric_families = prometheus::gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();

    Ok(warp::http::Response::builder()
        .header("Content-Type", encoder.format_type())
        .body(buffer))
}

pub async fn start_metrics(metrics_port: u16) {
    let metrics_route = warp::path!("metrics")
        .and(warp::get())
        .and_then(metrics_handler);

    tracing::info!("Starting metrics endpoint on: :{}", metrics_port);

    warp::serve(metrics_route)
        .run(([0, 0, 0, 0], metrics_port))
        .await;
}

#[derive(Debug, Clone, Deserialize)]
struct QueryParams {
    src: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PostBody {
    src: Option<String>,
    args: Option<Vec<(String, String)>>,
}

/// Starts the gateway server, returns a future that resolves when the server stops or fails
/// It exposes the following enpoints:
/// `GET /api/v1/services/{service}?src={service_provider}` -> invoke some service with the given provider
/// `POST /api/v1/services/{service} {src: ["{service_provider}"], args: [["{arg_name}", "{arg_value}"], ...]}` -> invoke some service with the given provider
pub async fn start(
    http_port: u16,
    service_manager: Arc<ServiceManager>,
    limit: u32,
    limit_window: u64,
) {
    let service_manager_clone = service_manager.clone();
    let service_manager_post_clone = service_manager.clone();

    let rate_limiter = Arc::new(RateLimiter::new(limit, Duration::from_secs(limit_window))); // 100 requests per minute

    let get_route = warp::path!("api" / "v1" / "services" / String)
        .and(warp::get())
        .and(with_auth(service_manager.clone()))
        .and(with_rate_limiter(rate_limiter.clone()))
        .and(warp::query::<QueryParams>())
        .and(warp::any().map(move || service_manager_clone.clone()))
        .and_then(handle_get);

    let post_route = warp::path!("api" / "v1" / "services" / String)
        .and(warp::post())
        .and(with_auth(service_manager.clone()))
        .and(with_rate_limiter(rate_limiter.clone()))
        .and(warp::body::content_length_limit(1024)) // limit to 1 KB payload
        .and(warp::body::json())
        .and(warp::query::<QueryParams>())
        .and(warp::any().map(move || service_manager_post_clone.clone()))
        .and_then(handle_post);

    //

    let routes = get_route.or(post_route);

    tracing::info!("Starting http server on: 0.0.0.0:{}", http_port);

    warp::serve(routes).run(([0, 0, 0, 0], http_port)).await;
}

async fn handle_get(
    service: String,
    _jwt: String,
    _: (),
    query: QueryParams,
    service_manager: Arc<ServiceManager>,
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
        vec![SRC_APTOS_ORBITAL.to_string(), SRC_DERIVED_TRNG.to_string()]
    };
    let svc_req = ServiceRequest {
        req_id,
        service,
        src,
        args: None,
    };
    handle_service_req(svc_req, service_manager.clone()).await
}

async fn handle_post(
    service: String,
    _jwt: String,
    _: (),
    body: PostBody,
    query: QueryParams,
    service_manager: Arc<ServiceManager>,
) -> Result<impl Reply, Rejection> {
    let req_id = new_req_id();
    let src = if let Some(s) = body.src {
        s.clone()
    } else {
        query.src.unwrap_or(SRC_APTOS_ORBITAL.to_string()).clone()
    };
    let args = body.args.clone();
    let svc_req = ServiceRequest {
        req_id,
        service,
        src: vec![src],
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
                tracing::debug!("[req={}] Got service result", req_id);
                Ok(warp::reply::json(&result))
            }
            Err(e) => {
                metrics::API_REQ_ERR_COUNTER
                    .with_label_values(&[&svc_name])
                    .inc();
                tracing::error!("[req={}] Error result: {:?}", req_id, e);
                Err(warp::reject::custom(e))
            }
        },
        Ok(Err(e)) => {
            metrics::API_REQ_FAILED_COUNTER
                .with_label_values(&[&svc_name])
                .inc();
            tracing::error!("[req={}] Error routing request: {:?}", req_id, e);
            Err(warp::reject::custom(e))
        }
        Err(_) => {
            metrics::API_REQ_TIMEOUT_COUNTER
                .with_label_values(&[&svc_name])
                .inc();
            tracing::error!("[req={}] Request timed out", req_id);
            Err(warp::reject::custom(ServiceError::ServiceTimeout))
        }
    }
}

/// Generates a new random request ID.
fn new_req_id() -> u64 {
    use rand::Rng;
    let mut rng = rand::rng();
    rng.random_range(1..u64::MAX)
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_jwt_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer test_token"));
        let jwt = jwt_from_header(&headers).unwrap();
        assert_eq!(jwt, "test_token");
    }

    #[tokio::test]
    async fn test_jwt_from_header_empty() {
        let headers = HeaderMap::new();
        match jwt_from_header(&headers) {
            Err(GatewayError::NoAuthHeaderError) => {}
            _ => panic!("Expected NoAuthHeaderError"),
        }
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let rate_limiter = Arc::new(RateLimiter::new(5, Duration::from_secs(10)));
        let token = format!("{}test_token", BEARER);

        for _i in 0..5 {
            rate_limit(Some(token.clone()), rate_limiter.clone())
                .await
                .unwrap();
        }
        match rate_limit(Some(token.clone()), rate_limiter.clone()).await {
            Ok(_) => panic!("Rate limit should have been exceeded"),
            Err(e) => {
                assert_eq!(
                    format!("{:?}", e),
                    "Rejection(RateLimitExceeded)".to_string(),
                    "Expected rate limit exceeded error"
                );
            }
        }
    }
}
