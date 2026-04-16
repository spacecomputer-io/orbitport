use clap::Parser;
use std::sync::Arc;
use tokio::sync::Notify;

use gateway::{logging, plugins, server, service_manager, types::GatewayError};

#[derive(Parser, Debug)]
struct Args {
    #[clap(short = 'p', long, env = "ORBITPORT_HTTP_PORT", default_value = "8080")]
    http_port: u16,
    #[clap(long, env = "ORBITPORT_METRICS_PORT", default_value = "9100")]
    metric_port: u16,
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
        dotenvy::dotenv().ok();
        dotenvy::from_filename(".gateway.env").ok();
        Self::parse()
    }
}

#[tokio::main]
async fn main() -> Result<(), GatewayError> {
    let _log_guard = logging::initialize_logging();

    let start = std::time::Instant::now();

    let args: Args = Args::with_dot_env();
    tracing::info!("Starting orbitport with args: {:?}", args);

    let plugin_catalog = gateway::plugins::PluginCatalog::from_env();

    // Plugins required by the gateway's built-in code paths.
    // Any *additional* plugin only needs an `ORBITPORT_PLUGIN_<NAME>` env
    // var — no code change here.
    let auth_url = plugin_catalog
        .url("auth")
        .ok_or_else(|| {
            GatewayError::ServiceConnectionError(
                "ORBITPORT_PLUGIN_AUTH must be set".to_string(),
            )
        })?
        .to_string();
    let masterseed_url = plugin_catalog
        .url("masterseed")
        .ok_or_else(|| {
            GatewayError::ServiceConnectionError(
                "ORBITPORT_PLUGIN_MASTERSEED must be set".to_string(),
            )
        })?
        .to_string();

    let shutdown = Arc::new(Notify::new());
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            match tokio::signal::ctrl_c().await {
                Ok(()) => shutdown.notify_waiters(),
                Err(err) => tracing::error!("Failed to listen for shutdown signal: {}", err),
            }
        });
    }

    plugins::wait_for(
        plugin_catalog.urls(),
        std::time::Duration::from_secs(60),
        shutdown.clone(),
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed while waiting for plugins to be healthy: {}", e);
        GatewayError::ServiceConnectionError(e.to_string())
    })?;
    let service_manager =
        service_manager::ServiceManager::new(&auth_url, &masterseed_url).await?;

    let metrics_port = args.metric_port;
    tokio::spawn(async move {
        gateway::metrics::start_server(metrics_port).await;
    });

    let service_manager = Arc::new(service_manager);
    let plugin_catalog = Arc::new(plugin_catalog);
    server::start(
        args.http_port,
        service_manager.clone(),
        plugin_catalog.clone(),
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
