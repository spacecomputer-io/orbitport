use std::sync::Arc;
use tonic::transport::Channel;

use crate::ctx;
use crate::service::{ServiceError, ServiceHandler, ServiceRequest, ServiceResponse};

use crate::trng::TrngService;

use crate::proto::auth::auth_agent_client::AuthAgentClient;

pub struct ServiceManager {
    auth_client: AuthAgentClient<Channel>,
    trng_svc: TrngService,
}

unsafe impl Send for ServiceManager {}

impl ServiceManager {
    pub async fn new(
        ctx: Arc<ctx::Context>,
        auth_url: &str,
        trng_url: &str,
    ) -> Result<ServiceManager, ServiceError> {
        let trng_svc = TrngService::new(ctx.clone(), trng_url, None, None)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create TRNG service: {}", e);
                ServiceError::ServiceConnectionError(e.to_string())
            })?;
        let auth_client = AuthAgentClient::connect(auth_url.to_string())
            .await
            .map_err(|e| {
                tracing::error!("Failed to connect to auth agent: {}", e);
                ServiceError::ServiceConnectionError(e.to_string())
            })?;

        Ok(ServiceManager {
            auth_client,
            trng_svc,
        })
    }

    pub fn get_auth_client(&self) -> AuthAgentClient<Channel> {
        self.auth_client.clone()
    }

    pub async fn handle(&self, svc_req: ServiceRequest) -> Result<ServiceResponse, ServiceError> {
        match svc_req.service {
            ref service if service == "trng" => {
                let mut svc = self.trng_svc.clone();
                let response = svc.handle(svc_req).await?;
                Ok(response)
            }
            ref service => Err(ServiceError::ServiceNotFoundError(service.clone())),
        }
    }
}
