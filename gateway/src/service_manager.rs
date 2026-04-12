use tonic::transport::Channel;

use crate::proto::plugins::masterseed::master_seed_plugin_client::MasterSeedPluginClient;
use crate::trng::TrngService;
use crate::types::{GatewayError, ServiceHandler, ServiceRequest, ServiceResponse};

use crate::proto::plugins::auth::auth_plugin_client::AuthPluginClient;
pub struct ServiceManager {
    auth_client: AuthPluginClient<Channel>,
    trng_svc: TrngService,
}

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
