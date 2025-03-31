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
            let service_manager = service_manager::ServiceManager::new(
                ctx_cloned, auth_agent.as_str(), trng_agent.as_str()
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
