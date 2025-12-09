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
