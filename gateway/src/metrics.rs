use prometheus::{self, HistogramVec, IntCounterVec};
use std::convert::Infallible;

use lazy_static::lazy_static;
use warp::{Filter, Reply};

lazy_static! {
    pub static ref TRNG_MASTER_SEED_COUNTER: IntCounterVec = prometheus::register_int_counter_vec!(
        "op_master_seed_total",
        "Number of times masterseed derivation was used",
        &["status"]
    )
    .unwrap();
    pub static ref API_REQ_COUNTER: IntCounterVec = prometheus::register_int_counter_vec!(
        "op_api_req_total",
        "Total number of requests to the gateway",
        &["service"]
    )
    .unwrap();
    pub static ref API_REQ_OK_COUNTER: IntCounterVec = prometheus::register_int_counter_vec!(
        "op_api_req_ok_total",
        "Total number of successful requests to the gateway",
        &["service"]
    )
    .unwrap();
    pub static ref API_REQ_ERR_COUNTER: IntCounterVec = prometheus::register_int_counter_vec!(
        "op_api_req_err_total",
        "Total number of errored requests to the gateway",
        &["service"]
    )
    .unwrap();
    pub static ref API_REQ_TIMEOUT_COUNTER: IntCounterVec = prometheus::register_int_counter_vec!(
        "op_api_req_timeout_total",
        "Total number of timed-out requests to the gateway",
        &["service"]
    )
    .unwrap();
    pub static ref API_REQ_FAILED_COUNTER: IntCounterVec = prometheus::register_int_counter_vec!(
        "op_api_req_failed_total",
        "Total number of failed requests to the gateway",
        &["service"]
    )
    .unwrap();
    pub static ref API_REQ_DURATION_SECONDS: HistogramVec = prometheus::register_histogram_vec!(
        "op_api_req_duration_seconds",
        "Duration of HTTP requests in seconds",
        &["service"]
    )
    .unwrap();
    static ref GATEWAY_REQUESTS_TOTAL: IntCounterVec = prometheus::register_int_counter_vec!(
        "op_gateway_requests_total",
        "Total number of gateway service requests",
        &["service", "status"]
    )
    .unwrap();
    static ref GATEWAY_REQUEST_DURATION_SECONDS: HistogramVec =
        prometheus::register_histogram_vec!(
            "op_gateway_request_duration_seconds",
            "Duration of gateway service requests in seconds",
            &["service", "status"]
        )
        .unwrap();
    static ref GATEWAY_TRNG_SOURCE_TOTAL: IntCounterVec = prometheus::register_int_counter_vec!(
        "op_gateway_trng_source_total",
        "Total number of gateway TRNG source outcomes",
        &["source", "status"]
    )
    .unwrap();
    static ref GATEWAY_AUTH_TOTAL: IntCounterVec = prometheus::register_int_counter_vec!(
        "op_gateway_auth_total",
        "Total number of gateway authentication attempts",
        &["status"]
    )
    .unwrap();
    static ref GATEWAY_AUTH_DURATION_SECONDS: HistogramVec = prometheus::register_histogram_vec!(
        "op_gateway_auth_duration_seconds",
        "Duration of gateway authentication attempts in seconds",
        &["status"]
    )
    .unwrap();
    static ref GATEWAY_RATE_LIMIT_TOTAL: IntCounterVec = prometheus::register_int_counter_vec!(
        "op_gateway_rate_limit_total",
        "Total number of gateway rate limit outcomes",
        &["status"]
    )
    .unwrap();
    static ref GATEWAY_VALIDATION_TOTAL: IntCounterVec = prometheus::register_int_counter_vec!(
        "op_gateway_validation_total",
        "Total number of gateway request validation outcomes",
        &["method", "reason"]
    )
    .unwrap();
}

pub fn record_request(service: &str, status: &str, duration_seconds: f64) {
    GATEWAY_REQUESTS_TOTAL
        .with_label_values(&[service, status])
        .inc();
    GATEWAY_REQUEST_DURATION_SECONDS
        .with_label_values(&[service, status])
        .observe(duration_seconds);
}

pub fn record_auth(status: &str, duration_seconds: f64) {
    GATEWAY_AUTH_TOTAL.with_label_values(&[status]).inc();
    GATEWAY_AUTH_DURATION_SECONDS
        .with_label_values(&[status])
        .observe(duration_seconds);
}

pub fn record_rate_limit(status: &str) {
    GATEWAY_RATE_LIMIT_TOTAL.with_label_values(&[status]).inc();
}

pub fn record_validation(method: &str, reason: &str) {
    GATEWAY_VALIDATION_TOTAL
        .with_label_values(&[method, reason])
        .inc();
}

pub fn record_trng_source(source: &str, status: &str) {
    GATEWAY_TRNG_SOURCE_TOTAL
        .with_label_values(&[source, status])
        .inc();
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

pub async fn start_server(metrics_port: u16) {
    let metrics_route = warp::path!("metrics")
        .and(warp::get())
        .and_then(metrics_handler);

    tracing::info!("Starting metrics endpoint on: :{}", metrics_port);

    warp::serve(metrics_route)
        .run(([0, 0, 0, 0], metrics_port))
        .await;
}
