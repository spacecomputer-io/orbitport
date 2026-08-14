use clap::Parser;
use std::sync::Arc;
use tokio::sync::Notify;

use gateway::{
    logging, plugins, server, service_manager,
    types::{GatewayError, Secret},
};

#[derive(Parser, Debug)]
struct Args {
    #[clap(short = 'p', long, env = "ORBITPORT_HTTP_PORT", default_value = "8080")]
    http_port: u16,
    /// Port for internal-only routes (PAT issuance). Must not be published by
    /// any load balancer or Ingress-backed Service.
    #[clap(long, env = "ORBITPORT_INTERNAL_PORT", default_value = "8081")]
    internal_port: u16,
    #[clap(long, env = "ORBITPORT_METRICS_PORT", default_value = "9100")]
    metric_port: u16,
    #[clap(long, env = "ORBITPORT_AUTH_PLUGIN")]
    auth_plugin: String,
    #[clap(long, env = "ORBITPORT_KMS_PLUGIN")]
    kms_plugin: String,
    #[clap(long, env = "ORBITPORT_THRESHOLD_ENABLED", default_value = "false")]
    threshold_enabled: bool,
    #[clap(long, env = "ORBITPORT_THRESHOLD_PLUGIN", default_value = "")]
    threshold_plugin: String,
    #[clap(long, env = "ORBITPORT_THRESHOLD_GROUPS", default_value = "")]
    threshold_groups: String,
    #[clap(long, env = "ORBITPORT_MASTERSEED_PLUGIN")]
    masterseed_plugin: String,
    /// Optional account plugin gRPC URL. When set, JWT-authenticated routes
    /// hold credits via the account plugin before serving the request and
    /// release on downstream failure.
    #[clap(long, env = "ORBITPORT_ACCOUNT_PLUGIN")]
    account_plugin: Option<String>,
    /// Optional issuer plugin gRPC URL. When set, the gateway serves the
    /// public JWKS route and the internal PAT issuance route.
    #[clap(long, env = "ORBITPORT_ISSUER_PLUGIN")]
    issuer_plugin: Option<String>,
    /// Shared secret guarding POST /internal/pat/issue.
    #[clap(long, env = "ORBITPORT_ISSUER_SHARED_SECRET")]
    issuer_shared_secret: Option<Secret>,
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

/// PAT revocation is only enforced on the account plugin's Hold path, so an
/// issuer without an account plugin mints tokens that can never be revoked.
fn validate_pat_revocation_gating(
    issuer_configured: bool,
    account_configured: bool,
) -> Result<(), String> {
    if !issuer_configured || account_configured {
        return Ok(());
    }
    Err(
        "ORBITPORT_ISSUER_PLUGIN is set but ORBITPORT_ACCOUNT_PLUGIN is not: PATs would be \
         mintable but never revocable (revocation is enforced on the account plugin's Hold \
         path). Set ORBITPORT_ACCOUNT_PLUGIN."
            .to_string(),
    )
}

#[tokio::main]
async fn main() -> Result<(), GatewayError> {
    let _log_guard = logging::initialize_logging();

    let start = std::time::Instant::now();

    let args: Args = Args::with_dot_env();
    tracing::info!("Starting orbitport with args: {:?}", args);

    validate_pat_revocation_gating(args.issuer_plugin.is_some(), args.account_plugin.is_some())
        .map_err(|e| {
            tracing::error!("{}", e);
            GatewayError::InternalError(e)
        })?;

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

    let mut plugin_urls = vec![
        args.auth_plugin.to_string(),
        args.kms_plugin.to_string(),
        args.masterseed_plugin.to_string(),
    ];
    if let Some(ref url) = args.account_plugin {
        plugin_urls.push(url.to_string());
    }
    if let Some(ref url) = args.issuer_plugin {
        plugin_urls.push(url.to_string());
    }
    if args.threshold_enabled {
        let threshold_plugin = args.threshold_plugin.trim();
        if threshold_plugin.is_empty() {
            return Err(GatewayError::BadRequest(
                "ORBITPORT_THRESHOLD_PLUGIN is required when ORBITPORT_THRESHOLD_ENABLED=true"
                    .to_string(),
            ));
        }
        plugin_urls.push(threshold_plugin.to_string());
    }

    plugins::wait_for(
        plugin_urls,
        std::time::Duration::from_secs(60),
        shutdown.clone(),
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed while waiting for plugins to be healthy: {}", e);
        GatewayError::ServiceConnectionError(e.to_string())
    })?;
    let service_manager =
        service_manager::ServiceManager::new(&args.auth_plugin, &args.masterseed_plugin).await?;

    let metrics_port = args.metric_port;
    tokio::spawn(async move {
        gateway::metrics::start_server(metrics_port).await;
    });

    let service_manager = Arc::new(service_manager);
    let threshold_groups = if args.threshold_enabled {
        gateway::services::threshold::ThresholdGroupRegistry::from_json(&args.threshold_groups)
            .map_err(|e| GatewayError::BadRequest(e.to_string()))?
    } else {
        gateway::services::threshold::ThresholdGroupRegistry::default()
    };
    let plugin_catalog = Arc::new(gateway::plugins::PluginCatalog::new(
        &args.auth_plugin,
        &args.masterseed_plugin,
        &args.kms_plugin,
        args.account_plugin.as_deref(),
        args.issuer_plugin.as_deref(),
        args.threshold_enabled,
        args.threshold_plugin.trim(),
        threshold_groups,
    ));

    server::start(
        args.http_port,
        args.internal_port,
        service_manager.clone(),
        plugin_catalog.clone(),
        args.rate_limit,
        args.rate_limit_window,
        args.bulk_max,
        args.issuer_shared_secret.clone().map(|s| s.0),
    )
    .await;

    let time_elapsed = start.elapsed();
    tracing::info!(
        "Orbitport finished after {} seconds",
        time_elapsed.as_secs_f64()
    );
    Ok(())
}

#[cfg(test)]
mod test {
    use super::{Secret, validate_pat_revocation_gating};

    /// `Args` is logged with `{:?}` at startup, so a leaky `Debug` here puts the
    /// PAT-minting secret in every log aggregator.
    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::from("super-secret-value");
        assert_eq!(format!("{s:?}"), "[redacted]");
        assert!(!format!("{s:?}").contains("super-secret-value"));
        assert!(!format!("{:?}", Some(s)).contains("super-secret-value"));
    }

    #[test]
    fn issuer_without_account_fails_closed() {
        assert!(validate_pat_revocation_gating(true, false).is_err());
    }

    #[test]
    fn other_combinations_pass() {
        assert!(validate_pat_revocation_gating(false, false).is_ok());
        assert!(validate_pat_revocation_gating(false, true).is_ok());
        assert!(validate_pat_revocation_gating(true, true).is_ok());
    }
}
