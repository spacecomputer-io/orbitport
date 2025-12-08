use std::collections::VecDeque;
use std::time::Duration;
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

pub async fn wait_for_deps(addrs: Vec<String>, max_delay: Duration) -> Result<(), String> {
    let mut retry_delay = Duration::from_secs(1);

    let start_time = std::time::Instant::now();

    tracing::info!("Waiting for dependencies to be healthy: {:?}", addrs);

    let mut remaining = VecDeque::from(addrs.clone());
    loop {
        let n = remaining.len();
        for _i in 0..n {
            let addr = remaining.pop_front().unwrap();
            match check_health(addr.as_str()).await {
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
        tokio::time::sleep(retry_delay).await;
        retry_delay = (retry_delay * 2).min(max_delay); // Exponential backoff
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

        let trng_svc = TrngService::new(masterseed_client).await.map_err(|e| {
            tracing::error!("Failed to create TRNG service: {}", e);
            GatewayError::ServiceConnectionError(e.to_string())
        })?;

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
