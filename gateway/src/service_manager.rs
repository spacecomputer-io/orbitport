use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tonic::transport::Channel;
use tonic_health::pb::{
    HealthCheckRequest, HealthCheckResponse, health_check_response::ServingStatus,
    health_client::HealthClient,
};

use crate::proto::masterseed::master_seed_plugin_client::MasterSeedPluginClient;
use crate::trng::TrngService;
use crate::types::{GatewayError, ServiceHandler, ServiceRequest, ServiceResponse};

use crate::proto::auth::auth_plugin_client::AuthPluginClient;

async fn check_health(addr: &str) -> Result<HealthCheckResponse, tonic::Status> {
    let channel = Channel::from_shared(addr.to_string())
        .map_err(|e| tonic::Status::unavailable(format!("Failed to create channel: {e}")))?
        .connect()
        .await
        .map_err(|e| tonic::Status::unavailable(format!("Failed to connect to {addr}: {e}")))?;
    let mut client = HealthClient::new(channel);
    let request = HealthCheckRequest::default();
    client
        .check(request)
        .await
        .map(|response| response.into_inner())
}

pub async fn wait_for_deps(
    addrs: Vec<String>,
    max_retry_delay: Duration,
    shutdown: Arc<Notify>,
) -> Result<(), GatewayError> {
    let mut retry_delay = Duration::from_secs(1);
    let start_time = std::time::Instant::now();
    let shutdown = shutdown.notified();
    tokio::pin!(shutdown);

    tracing::info!(
        "Waiting for dependencies to be healthy before serving traffic: {:?}",
        addrs
    );

    let mut remaining = VecDeque::from(addrs);
    loop {
        let n = remaining.len();
        for _i in 0..n {
            let Some(addr) = remaining.pop_front() else {
                break;
            };
            let health_result = tokio::select! {
                _ = &mut shutdown => {
                    return Err(GatewayError::TerminationError(
                        "Received shutdown signal while waiting for dependencies".to_string(),
                    ));
                }
                result = check_health(addr.as_str()) => result,
            };
            match health_result {
                Ok(response) => {
                    if response.status() != ServingStatus::Serving {
                        tracing::debug!(
                            "Plugin {} is not serving. Status: {:?}",
                            addr,
                            response.status()
                        );
                        remaining.push_back(addr);
                    } else {
                        tracing::debug!("Plugin {} is serving.", addr);
                    }
                }
                Err(e) => {
                    tracing::debug!("Failed to check health for {}: {}", addr, e);
                    remaining.push_back(addr);
                }
            }
        }
        if remaining.is_empty() {
            let elapsed_time = start_time.elapsed();
            tracing::info!(
                "All dependencies are healthy. Time elapsed: {:?}",
                elapsed_time
            );
            return Ok(());
        }
        let elapsed_time = start_time.elapsed();
        tracing::warn!(
            "Not all dependencies are healthy. Time elapsed: {:?}. Retrying in {:?}",
            elapsed_time,
            retry_delay
        );
        tokio::select! {
            _ = &mut shutdown => {
                return Err(GatewayError::TerminationError(
                    "Received shutdown signal while waiting for dependencies".to_string(),
                ));
            }
            _ = tokio::time::sleep(retry_delay) => {}
        }
        retry_delay = (retry_delay * 2).min(max_retry_delay); // Exponential backoff
    }
}

pub async fn wait_for_service_manager(
    auth_url: &str,
    masterseed_url: &str,
    max_retry_delay: Duration,
    shutdown: Arc<Notify>,
) -> Result<ServiceManager, GatewayError> {
    wait_for_deps(
        vec![auth_url.to_string(), masterseed_url.to_string()],
        max_retry_delay,
        shutdown.clone(),
    )
    .await?;

    let mut retry_delay = Duration::from_secs(1);
    let start_time = std::time::Instant::now();
    let shutdown = shutdown.notified();
    tokio::pin!(shutdown);

    loop {
        let service_manager_result = tokio::select! {
            _ = &mut shutdown => {
                return Err(GatewayError::TerminationError(
                    "Received shutdown signal while initializing service manager".to_string(),
                ));
            }
            result = ServiceManager::new(auth_url, masterseed_url) => result,
        };

        match service_manager_result {
            Ok(service_manager) => {
                tracing::info!(
                    "Service manager initialized successfully after {:?}",
                    start_time.elapsed()
                );
                return Ok(service_manager);
            }
            Err(err) => {
                tracing::warn!(
                    "Failed to initialize service manager after {:?}: {}. Retrying in {:?}",
                    start_time.elapsed(),
                    err,
                    retry_delay
                );
            }
        }

        tokio::select! {
            _ = &mut shutdown => {
                return Err(GatewayError::TerminationError(
                    "Received shutdown signal while initializing service manager".to_string(),
                ));
            }
            _ = tokio::time::sleep(retry_delay) => {}
        }
        retry_delay = (retry_delay * 2).min(max_retry_delay);
    }
}

pub struct ServiceManager {
    auth_client: AuthPluginClient<Channel>,
    trng_svc: TrngService,
}

unsafe impl Send for ServiceManager {}

impl ServiceManager {
    pub async fn new(auth_url: &str, masterseed_url: &str) -> Result<ServiceManager, GatewayError> {
        let masterseed_client = MasterSeedPluginClient::connect(masterseed_url.to_string())
            .await
            .map_err(|e| GatewayError::ServiceConnectionError(e.to_string()))?;

        let trng_svc = TrngService::new(masterseed_client);

        let auth_client = AuthPluginClient::connect(auth_url.to_string())
            .await
            .map_err(|e| {
                tracing::error!("Failed to connect to auth plugin: {}", e);
                GatewayError::ServiceConnectionError(e.to_string())
            })?;

        Ok(ServiceManager {
            auth_client,
            trng_svc,
        })
    }

    pub fn get_auth_client(&self) -> AuthPluginClient<Channel> {
        self.auth_client.clone()
    }

    pub async fn handle(&self, svc_req: ServiceRequest) -> Result<ServiceResponse, GatewayError> {
        match svc_req.service {
            ref service if service == "trng" => {
                let mut svc = self.trng_svc.clone();
                let response = svc.handle(svc_req).await?;
                Ok(response)
            }
            ref service => Err(GatewayError::ServiceNotFoundError(service.clone())),
        }
    }
}
