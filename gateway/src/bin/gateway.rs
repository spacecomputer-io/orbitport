use clap::Parser;
use std::sync::Arc;
use thiserror::Error;

use gateway::{ctx, logging, os_signals, server, service_manager};

#[derive(Error, Debug)]
pub enum OpRuntimeError {
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(short = 'p', long, env = "ORBITPORT_HTTP_PORT", default_value = "8080")]
    http_port: u16,
    #[clap(long, env = "ORBITPORT_AUTH_AGENT")]
    auth_agent: String,
    #[clap(long, env = "ORBITPORT_TRNG_AGENT")]
    trng_agent: String,
    #[clap(long, env = "ORBITPORT_DEFAULT_MASTER_SEED")]
    default_master_seed: Option<String>,
    #[clap(long, env = "ORBITPORT_MASTER_SEED_INTERVAL")]
    master_seed_interval: Option<u64>,
}

impl Args {
    pub fn with_dot_env() -> Self {
        dotenv::dotenv().ok();
        dotenv::from_filename(".gateway.env").ok();
        Self::parse()
    }
}

#[tokio::main]
async fn main() -> Result<(), OpRuntimeError> {
    let _log_guard = logging::initialize_logging();

    let start = std::time::Instant::now();

    let ctx = Arc::new(ctx::Context::new());
    let ctx_cloned = ctx.clone();

    let args: Args = Args::with_dot_env();
    tracing::info!("Starting orbitport with args: {:?}", args);

    // let ctx_cloned = ctx.clone();
    let auth_agent = args.auth_agent.clone();
    let trng_agent = args.trng_agent.clone();
    tokio::select! {
        _ = tokio::spawn(async move {
            service_manager::wait_for_deps(
                vec![auth_agent.clone(), trng_agent.clone()],
                std::time::Duration::from_secs(60),
            ).await.unwrap();

            let service_manager = service_manager::ServiceManager::new(
                ctx_cloned, auth_agent.as_str(), trng_agent.as_str(),
                args.master_seed_interval, args.default_master_seed,
            ).await.unwrap();

            let service_manager = Arc::new(service_manager);
            // Start the server
            server::start(args.http_port, service_manager.clone()).await;

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
