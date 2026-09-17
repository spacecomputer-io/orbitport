use prometheus::{self, HistogramVec, IntCounterVec};
use std::convert::Infallible;

use lazy_static::lazy_static;
use warp::{Filter, Reply};

lazy_static! {
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
    static ref GATEWAY_ACCOUNT_HOLD_TOTAL: IntCounterVec = prometheus::register_int_counter_vec!(
        "op_gateway_account_hold_total",
        "Total number of account-plugin Hold outcomes",
        &["status"]
    )
    .unwrap();
    static ref GATEWAY_ACCOUNT_RELEASE_TOTAL: IntCounterVec =
        prometheus::register_int_counter_vec!(
            "op_gateway_account_release_total",
            "Total number of account-plugin Release outcomes",
            &["status"]
        )
        .unwrap();
    static ref GATEWAY_ACCOUNT_SETTLE_TOTAL: IntCounterVec = prometheus::register_int_counter_vec!(
        "op_gateway_account_settle_total",
        "Total number of account-plugin Settle outcomes",
        &["status"]
    )
    .unwrap();
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

pub fn record_account_hold(status: &str) {
    GATEWAY_ACCOUNT_HOLD_TOTAL
        .with_label_values(&[status])
        .inc();
}

pub fn record_account_release(status: &str) {
    GATEWAY_ACCOUNT_RELEASE_TOTAL
        .with_label_values(&[status])
        .inc();
}

pub fn record_account_settle(status: &str) {
    GATEWAY_ACCOUNT_SETTLE_TOTAL
        .with_label_values(&[status])
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
