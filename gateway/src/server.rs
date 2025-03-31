use serde::Deserialize;
use std::sync::Arc;
use thiserror::Error;
use tokio::time::{Duration, timeout};
use tonic::transport::Channel;
use warp::{
    Filter, Rejection, Reply,
    filters::header::headers_cloned,
    http::header::{AUTHORIZATION, HeaderMap, HeaderValue},
    reject::Reject,
};

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
}

impl Reject for GatewayError {}

impl Reject for ServiceError {}

const BEARER: &str = "Bearer ";

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
                .map_err(|e| {
                    tracing::error!("Failed to authorize JWT: {}", e);
                    warp::reject::custom(GatewayError::AuthenticationFailed)
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
    if !auth_header.starts_with(BEARER) {
        return Err(GatewayError::InvalidAuthHeaderError);
    }
    Ok(auth_header.trim_start_matches(BEARER).to_owned())
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
///
pub async fn start(http_port: u16, service_manager: Arc<ServiceManager>) {
    let service_manager_clone = service_manager.clone();
    let service_manager_post_clone = service_manager.clone();

    let get_route = warp::path!("api" / "v1" / "services" / String)
        .and(warp::get())
        .and(with_auth(service_manager.clone()))
        .and(warp::query::<QueryParams>())
        .and(warp::any().map(move || service_manager_clone.clone()))
        .and_then(handle_get);

    let post_route = warp::path!("api" / "v1" / "services" / String)
        .and(warp::post())
        .and(with_auth(service_manager.clone()))
        .and(warp::body::content_length_limit(1024 * 1024)) // Limit to 1 MB
        .and(warp::body::json())
        .and(warp::query::<QueryParams>())
        .and(warp::any().map(move || service_manager_post_clone.clone()))
        .and_then(handle_post);

    let routes = get_route.or(post_route);

    tracing::info!("Starting http server on: 0.0.0.0:{}", http_port);

    warp::serve(routes).run(([0, 0, 0, 0], http_port)).await;
}

async fn handle_get(
    service: String,
    _jwt: String,
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
    let req_id = svc_req.req_id;
    let response = timeout(Duration::from_secs(10), async {
        service_manager.handle(svc_req).await
    })
    .await;

    match response {
        Ok(Ok(res)) => match res.result {
            Ok(result) => {
                tracing::debug!("[req={}] Got service result", req_id);
                Ok(warp::reply::json(&result))
            }
            Err(e) => {
                tracing::error!("[req={}] Error result: {:?}", req_id, e);
                Err(warp::reject::custom(e))
            }
        },
        Ok(Err(e)) => {
            tracing::error!("[req={}] Error routing request: {:?}", req_id, e);
            Err(warp::reject::custom(e))
        }
        Err(_) => {
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
