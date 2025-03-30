use tonic::transport::Channel;

use crate::proto::trng::{
    TrngRequest, TrngResponse, randomness_agent_client::RandomnessAgentClient,
};

use crate::service::{
    Service, ServiceError, ServiceRequest, ServiceResponse, ServiceResult, Signature,
};

/// The src used for aptos orbital services
pub const SRC_APTOS_ORBITAL: &str = "aptosorbital";
/// The service name for trng (true random number generator)
pub const SERVICE_TRNG: &str = "trng";

/// The TrngService is a service that provides access to the Aptos Orbital
/// randomness agent. It is used to generate true random numbers.
#[derive(Clone)]
pub struct TrngService {
    pub aptos_orbital_client: RandomnessAgentClient<Channel>,
}

impl TrngService {
    /// Creates a new instance of the TrngService.
    pub async fn new(trng_url: &str) -> Result<Self, ServiceError> {
        let aptos_orbital_client = RandomnessAgentClient::connect(trng_url.to_string())
            .await
            .map_err(|e| {
                tracing::error!("Failed to connect to randomness agent: {}", e);
                ServiceError::ServiceConnectionError(e.to_string())
            })?;
        Ok(TrngService {
            aptos_orbital_client,
        })
    }
}

impl Service for TrngService {
    async fn handle(&mut self, svc_req: ServiceRequest) -> Result<ServiceResponse, ServiceError> {
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
}
