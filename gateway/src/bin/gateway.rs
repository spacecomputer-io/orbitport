use clap::Parser;
use std::sync::Arc;

use gateway::{logging, server, service_manager, types::GatewayError};

#[derive(Parser, Debug)]
struct Args {
    #[clap(short = 'p', long, env = "ORBITPORT_HTTP_PORT", default_value = "8080")]
    http_port: u16,
    #[clap(long, env = "ORBITPORT_METRICS_PORT", default_value = "9100")]
    metric_port: u16,
    #[clap(long, env = "ORBITPORT_HEALTH_PORT", default_value = "8081")]
    health_port: u16,
    #[clap(long, env = "ORBITPORT_AUTH_PLUGIN")]
    auth_plugin: String,
    #[clap(long, env = "ORBITPORT_MASTERSEED_PLUGIN")]
    masterseed_plugin: String,
    /// Rate limit per access token, 4 requests per second
    /// (40 requests per 10 seconds window)
    #[clap(long, env = "ORBITPORT_RATE_LIMIT", default_value = "40")]
    rate_limit: u32,
    #[clap(long, env = "ORBITPORT_RATE_LIMIT_WINDOW", default_value = "10")]
    rate_limit_window: u64,
    #[clap(long, env = "ORBITPORT_BULK_MAX", default_value = "10")]
    bulk_max: usize,
}

impl Args {
    pub fn with_dot_env() -> Self {
        dotenv::dotenv().ok();
        dotenv::from_filename(".gateway.env").ok();
        Self::parse()
    }
}

#[tokio::main]
async fn main() -> Result<(), GatewayError> {
    let _log_guard = logging::initialize_logging();

    let start = std::time::Instant::now();

    let args: Args = Args::with_dot_env();
    tracing::info!("Starting orbitport with args: {:?}", args);

    service_manager::wait_for_deps(
        vec![args.auth_plugin.clone(), args.masterseed_plugin.clone()],
        std::time::Duration::from_secs(60),
    )
    .await
    .unwrap();

    let service_manager = service_manager::ServiceManager::new(
        args.auth_plugin.as_str(),
        args.masterseed_plugin.as_str(),
    )
    .await
    .unwrap();

    let health_port = args.health_port;
    tokio::spawn(async move {
        gateway::health::start_health_check_server(health_port).await;
    });

    let metrics_port = args.metric_port;
    tokio::spawn(async move {
        gateway::metrics::start_server(metrics_port).await;
    });

    let service_manager = Arc::new(service_manager);
    server::start(
        args.http_port,
        service_manager.clone(),
        args.rate_limit,
        args.rate_limit_window,
        args.bulk_max,
    )
    .await;

    let time_elapsed = start.elapsed();
    tracing::info!(
        "Orbitport finished after {} seconds",
        time_elapsed.as_secs_f64()
    );
    Ok(())
}
