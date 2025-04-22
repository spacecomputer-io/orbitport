use prometheus::{self, HistogramVec, IntCounterVec, IntGauge};

use lazy_static::lazy_static;

lazy_static! {
    pub static ref TRNG_MASTER_SEEDS: IntGauge = prometheus::register_int_gauge!(
        "op_trng_master_seed_total",
        "Number of master seeds used for derivation of randomness"
    )
    .unwrap();
    pub static ref TRNG_FALLBACKS_COUNTER: IntCounterVec = prometheus::register_int_counter_vec!(
        "op_trng_fallbacks_total",
        "Number of times the fallback mechanism was used",
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
