use warp::Filter;

use tracing::{debug, info};

/// Starts a health check server on the specified port.
/// Using warp to create a simple HTTP server that responds to /health with 200 OK and payload {"status": "ok"}.
pub async fn start_health_check_server(port: u16) {
    let health_route = warp::path("health").map(|| {
        debug!("Received health check request");
        warp::reply::json(&serde_json::json!({
            "status": "ok"
        }))
    });

    let routes = health_route.with(warp::log("health_check"));

    info!("Starting health check server on port {}", port);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}
