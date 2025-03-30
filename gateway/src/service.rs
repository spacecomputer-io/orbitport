use crate::common::{
    SERVICE_TRNG, SRC_APTOS_ORBITAL, ServiceError, ServiceRequest, ServiceResponse, ServiceResult,
    Signature,
};

use crate::proto::auth::auth_agent_client::AuthAgentClient;
use crate::proto::trng::{
    TrngRequest, TrngResponse, randomness_agent_client::RandomnessAgentClient,
};

use tonic::transport::Channel;

pub struct ServiceManager {
    auth_client: AuthAgentClient<Channel>,
    aptos_orbital_client: RandomnessAgentClient<Channel>,
}

impl ServiceManager {
    pub async fn new(auth_url: &str, trng_url: &str) -> Result<ServiceManager, ServiceError> {
        let aptos_orbital_client = RandomnessAgentClient::connect(trng_url.to_string())
            .await
            .map_err(|e| {
                tracing::error!("Failed to connect to randomness agent: {}", e);
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
            aptos_orbital_client,
        })
    }

    pub fn get_auth_client(&self) -> AuthAgentClient<Channel> {
        self.auth_client.clone()
    }

    pub async fn handle(&self, svc_req: ServiceRequest) -> Result<ServiceResponse, ServiceError> {
        match svc_req.service {
            ref service if service == "trng" => {
                let mut client = self.aptos_orbital_client.clone();
                let request = TrngRequest {
                    ignore_sig: false,
                    chunks: 1,
                };
                let trng: TrngResponse = client
                    .get_trng(request)
                    .await
                    .map_err(|e| {
                        tracing::warn!("Failed to get trng: {}", e);
                        ServiceError::InternalError("Failed to get trng".to_string())
                    })?
                    .into_inner();
                let response = ServiceResponse {
                    req_id: svc_req.req_id,
                    result: Ok(ServiceResult {
                        service: SERVICE_TRNG.to_string(),
                        src: SRC_APTOS_ORBITAL.to_string(),
                        data: trng.value.clone(),
                        signature: Signature {
                            value: trng.sig.clone(),
                            pk: "".to_string(),
                            algo: "".to_string(),
                        },
                    }),
                };
                Ok(response)
            }
            ref service => Err(ServiceError::ServiceNotFoundError(service.clone())),
        }
    }
}
