use prometheus::{self, HistogramVec, IntCounterVec};
use std::convert::Infallible;

use lazy_static::lazy_static;
use warp::{Filter, Reply};

lazy_static! {
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
}

pub fn record_request(service: &str, status: &str, duration_seconds: f64) {
    GATEWAY_REQUESTS_TOTAL
        .with_label_values(&[service, status])
        .inc();
    GATEWAY_REQUEST_DURATION_SECONDS
        .with_label_values(&[service, status])
        .observe(duration_seconds);
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
