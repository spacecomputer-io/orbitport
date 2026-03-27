use std::path::Path;

use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

use tracing_appender::non_blocking::WorkerGuard;

/// Initializes logging
pub fn initialize_logging() -> WorkerGuard {
    // Parse the `RUST_LOG_SPAN_EVENTS` environment variable
    let span_event_filter = match std::env::var("RUST_LOG_SPAN_EVENTS") {
        Ok(val) => val
            .split(',')
            .map(|s| match s.trim() {
                "new" => FmtSpan::NEW,
                "enter" => FmtSpan::ENTER,
                "exit" => FmtSpan::EXIT,
                "close" => FmtSpan::CLOSE,
                "active" => FmtSpan::ACTIVE,
                "full" => FmtSpan::FULL,
                _ => FmtSpan::NONE,
            })
            .fold(FmtSpan::NONE, |acc, x| acc | x),
        Err(_) => FmtSpan::NONE,
    };

    let (log_writer, guard) = get_log_file_writer();

    // Conditionally initialize in `json` mode
    if std::env::var("RUST_LOG_FORMAT") == Ok("json".to_string()) {
        match tracing_subscriber::fmt()
            .with_writer(log_writer)
            .with_env_filter(EnvFilter::from_default_env())
            .with_span_events(span_event_filter)
            .json()
            .try_init()
        {
            Ok(()) => tracing::info!("Logging initialized"),
            Err(err) => eprintln!("Failed to initialize logging: {err}"),
        };
    } else {
        match tracing_subscriber::fmt()
            .with_writer(log_writer)
            .with_env_filter(EnvFilter::from_default_env())
            .with_span_events(span_event_filter)
            .try_init()
        {
            Ok(()) => tracing::info!("Logging initialized"),
            Err(err) => eprintln!("Failed to initialize logging: {err}"),
        };
    };
    // Return the guard to ensure logs are flushed
    guard
}

/// Returns a log writer based on `RUST_LOG_FILE`.
/// When `RUST_LOG_FILE` is set, logs are written to a daily-rolled file managed by the process.
/// Otherwise logs are written to stdout for container/runtime log collection.
fn get_log_file_writer() -> (tracing_appender::non_blocking::NonBlocking, WorkerGuard) {
    if let Ok(log_file_path) = std::env::var("RUST_LOG_FILE") {
        let log_path = Path::new(&log_file_path);
        let directory = log_path.parent().unwrap_or_else(|| Path::new("."));
        let prefix = log_path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("gateway.log");

        let writer = tracing_appender::rolling::daily(directory, prefix);
        let (non_blocking, guard) = tracing_appender::non_blocking(writer);
        return (non_blocking, guard);
    }
    // Defaults to stdout if no log file is specified
    let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
    (non_blocking, guard)
}
