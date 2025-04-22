use tokio::{select, signal};
use tracing::debug;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum OsSignalsError {
    #[error("Error while waiting for termination signal: {0}")]
    TerminationError(String),
}

pub async fn wait_exit_signals() -> Result<(), OsSignalsError> {
    let mut terminate = signal::unix::signal(signal::unix::SignalKind::terminate())
        .map_err(|e| OsSignalsError::TerminationError(e.to_string()))?;
    let mut interrupt = signal::unix::signal(signal::unix::SignalKind::interrupt())
        .map_err(|e| OsSignalsError::TerminationError(e.to_string()))?;
    let mut quit = signal::unix::signal(signal::unix::SignalKind::quit())
        .map_err(|e| OsSignalsError::TerminationError(e.to_string()))?;

    select! {
        _ = terminate.recv() => {
            debug!("Received terminate signal");
        }
        _ = interrupt.recv() => {
            debug!("Received interrupt signal");
        }
        _ = quit.recv() => {
            debug!("Received quit signal");
        }
    }

    Ok(())
}
