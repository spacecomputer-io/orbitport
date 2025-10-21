use clap::Parser;
use std::sync::Arc;

use gateway::{ctx, logging, os_signals, server, service_manager, types::GatewayError};

#[derive(Parser, Debug)]
struct Args {
    #[clap(short = 'p', long, env = "ORBITPORT_HTTP_PORT", default_value = "8080")]
    http_port: u16,
    #[clap(long, env = "ORBITPORT_METRICS_PORT", default_value = "9100")]
    metric_port: u16,
    #[clap(long, env = "ORBITPORT_AUTH_PLUGIN")]
    auth_plugin: String,
    #[clap(long, env = "ORBITPORT_TRNG_PLUGIN")]
    trng_plugin: String,
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

    let ctx = Arc::new(ctx::Context::new());
    let ctx_cloned = ctx.clone();

    let args: Args = Args::with_dot_env();
    tracing::info!("Starting orbitport with args: {:?}", args);

    // let ctx_cloned = ctx.clone();
    let auth_plugin = args.auth_plugin.clone();
    let trng_plugin = args.trng_plugin.clone();
    tokio::select! {
        _ = tokio::spawn(async move {
            service_manager::wait_for_deps(
                vec![auth_plugin.clone(), trng_plugin.clone()],
                std::time::Duration::from_secs(60),
            ).await.unwrap();

            let service_manager = service_manager::ServiceManager::new(
                ctx_cloned,
                auth_plugin.as_str(),
                trng_plugin.as_str(),
                args.masterseed_plugin.as_str(),
            ).await.unwrap();

            let metrics_port = args.metric_port;
            tokio::spawn(async move {
                gateway::metrics::start_server(metrics_port).await;
            });

            let service_manager = Arc::new(service_manager);
            server::start(args.http_port, service_manager.clone(), args.rate_limit, args.rate_limit_window, args.bulk_max).await;

            let time_elapsed = start.elapsed();
            tracing::info!(
                "Orbitport finished after {} seconds",
                time_elapsed.as_secs_f64()
            );
        }) => {}
        _ = os_signals::wait_exit_signals() => {
            ctx.stop();
        }
    }
    Ok(())
}
