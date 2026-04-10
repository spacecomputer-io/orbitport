use crate::metrics;
use crate::proto::plugins::auth::{
    TokenValidationRequest, TokenValidationResponse, auth_plugin_client::AuthPluginClient,
};
use crate::types::GatewayError;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    sync::Mutex,
    time::{Duration, Instant},
};
use tonic::transport::Channel;
use warp::{
    Filter,
    filters::header::headers_cloned,
    http::header::{AUTHORIZATION, HeaderMap, HeaderValue},
};

const BEARER: &str = "Bearer ";

/// Rate limit structure
pub type RateLimit = (u32, Instant);
/// Rate limit items
type RateLimiterItems = Arc<Mutex<HashMap<String, RateLimit>>>;

/// Rate limiter structure that holds the rate limit items, maximum requests allowed,
/// and the time window for rate limiting.
pub struct RateLimiter {
    items: RateLimiterItems,
    max_requests: u32,
    time_window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: u32, time_window: Duration) -> Self {
        RateLimiter {
            items: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            time_window,
        }
    }
}

/// Creates an authentication filter that validates JWTs using the auth plugin.
pub fn with_auth(
    auth_client: AuthPluginClient<Channel>,
) -> impl Filter<Extract = (String,), Error = warp::Rejection> + Clone {
    headers_cloned()
        .map(move |headers: HeaderMap<HeaderValue>| (headers, auth_client.clone()))
        .and_then(authorize)
}

type ApiResult<T> = std::result::Result<T, warp::Rejection>;

/// Authorization logic that extracts the JWT from the Authorization header,
/// validates it using the auth plugin, and returns the JWT if valid.
async fn authorize(
    (headers, mut auth_client): (HeaderMap<HeaderValue>, AuthPluginClient<Channel>),
) -> ApiResult<String> {
    let timer = Instant::now();
    match jwt_from_header(&headers) {
        Ok(jwt) => {
            let request = tonic::Request::new(TokenValidationRequest { token: jwt.clone() });
            let response: TokenValidationResponse = auth_client
                .validate_token(request)
                .await
                .map_err(|e| match e.code() {
                    tonic::Code::Unavailable | tonic::Code::NotFound => {
                        metrics::record_auth("plugin_unavailable", timer.elapsed().as_secs_f64());
                        tracing::error!("Auth plugin is unavailable: {}", e);
                        warp::reject::custom(GatewayError::AuthPluginConnectionError(
                            "unavailable".to_string(),
                        ))
                    }
                    _ => {
                        metrics::record_auth("failed", timer.elapsed().as_secs_f64());
                        tracing::error!("Failed to authorize JWT: {}", e);
                        warp::reject::custom(GatewayError::AuthenticationFailed)
                    }
                })?
                .into_inner();
            if !response.ok {
                metrics::record_auth("rejected", timer.elapsed().as_secs_f64());
                return Err(warp::reject::custom(GatewayError::AuthenticationFailed));
            }
            metrics::record_auth("ok", timer.elapsed().as_secs_f64());
            tracing::debug!("JWT authorized successfully");
            Ok(jwt)
        }
        Err(GatewayError::NoAuthHeaderError) => {
            metrics::record_auth("missing_header", timer.elapsed().as_secs_f64());
            Err(warp::reject::custom(GatewayError::NoAuthHeaderError))
        }
        Err(GatewayError::InvalidAuthHeaderError) => {
            metrics::record_auth("invalid_header", timer.elapsed().as_secs_f64());
            Err(warp::reject::custom(GatewayError::InvalidAuthHeaderError))
        }
        Err(e) => {
            metrics::record_auth("failed", timer.elapsed().as_secs_f64());
            Err(warp::reject::custom(e))
        }
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
    auth_filter: impl Filter<Extract = (String,), Error = warp::Rejection> + Clone,
    rate_limiter: Arc<RateLimiter>,
) -> impl Filter<Extract = (String,), Error = warp::Rejection> + Clone {
    auth_filter
        .and(warp::any().map(move || rate_limiter.clone()))
        .and_then(rate_limit)
}

/// Rate limiting logic.
async fn rate_limit(
    jwt: String,
    rate_limiter: Arc<RateLimiter>,
) -> Result<String, warp::Rejection> {
    // Hash the token to avoid storing it directly.
    let mut hasher = Sha256::new();
    hasher.update(&jwt);
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
        metrics::record_rate_limit("exceeded");
        return Err(warp::reject::custom(GatewayError::RateLimitExceeded)); // Use a custom rejection
    }

    metrics::record_rate_limit("ok");
    Ok(jwt)
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
        let token = "test_token".to_string();

        for _i in 0..5 {
            rate_limit(token.clone(), rate_limiter.clone())
                .await
                .unwrap();
        }
        match rate_limit(token.clone(), rate_limiter.clone()).await {
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
