use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tonic::transport::Channel;

use crate::proto::plugins::threshold::{
    DkgRequest as PluginDkgRequest, DkgResponse as PluginDkgResponse,
    GroupMember as PluginGroupMember, threshold_plugin_client::ThresholdPluginClient,
};
use crate::proto::services::threshold::{DkgRequest, DkgResponse};

const MAX_ALIAS_LEN: usize = 128;
const KEY_ID_PREFIX: &str = "threshold:";
const DKG_COMPLETED_STATUS: &str = "dkg_completed";

/// Validation and configuration errors for the threshold service.
#[derive(Error, Debug)]
pub enum ThresholdError {
    #[error("Invalid threshold groups config: {0}")]
    InvalidGroupsConfig(#[from] serde_json::Error),
    #[error("{0} is required")]
    MissingField(&'static str),
    #[error("{0} must not contain surrounding whitespace")]
    SurroundingWhitespace(&'static str),
    #[error("alias must be at most {0} characters")]
    AliasTooLong(usize),
    #[error("alias must not use the reserved threshold:<alias> format")]
    AliasReservedPrefix,
    #[error("alias contains unsupported characters")]
    AliasUnsupportedCharacters,
    #[error("Threshold group {0} requires at least two participants")]
    NotEnoughParticipants(String),
    #[error("Threshold group {0} threshold must be between 2 and participant count")]
    ThresholdOutOfRange(String),
    #[error("Threshold group {group} has duplicate participant node_id {node_id}")]
    DuplicateNodeId { group: String, node_id: String },
    #[error("Participant {node_id} party_index {party_index} out of range")]
    PartyIndexOutOfRange { node_id: String, party_index: i32 },
    #[error("Threshold group {group} has duplicate participant party_index {party_index}")]
    DuplicatePartyIndex { group: String, party_index: i32 },
}

#[derive(Clone, Debug, Default)]
pub struct ThresholdGroupRegistry {
    groups: Arc<HashMap<String, ThresholdGroupConfig>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ThresholdGroupConfig {
    threshold: i32,
    participants: Vec<GroupMemberConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GroupMemberConfig {
    node_id: String,
    party_index: i32,
    openbao_url: String,
    #[serde(default)]
    mount: String,
}

impl ThresholdGroupRegistry {
    pub fn from_json(raw: &str) -> Result<Self, ThresholdError> {
        if raw.trim().is_empty() {
            return Ok(Self::default());
        }

        let groups: HashMap<String, ThresholdGroupConfig> = serde_json::from_str(raw)?;
        for (name, group) in &groups {
            validate_group_config(name, group)?;
        }

        Ok(Self {
            groups: Arc::new(groups),
        })
    }

    fn get(&self, name: &str) -> Option<ThresholdGroupConfig> {
        self.groups.get(name).cloned()
    }
}

#[derive(Debug)]
pub enum ThresholdRpcCall {
    CoordinateDkg(DkgRequest),
}

impl ThresholdRpcCall {
    pub fn validate(&self) -> Result<(), ThresholdError> {
        match self {
            Self::CoordinateDkg(req) => ThresholdService::validate_coordinate_dkg(req),
        }
    }

    fn log_start(&self, req_id: u64) {
        match self {
            Self::CoordinateDkg(req) => tracing::debug!(
                "Executing Threshold CoordinateDkg RPC [id={} alias={} group_name={}]",
                req_id,
                req.alias,
                req.group_name
            ),
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum ThresholdRpcResult {
    CoordinateDkg(DkgResponse),
}

impl ThresholdRpcResult {
    fn log_success(&self, req_id: u64) {
        match self {
            Self::CoordinateDkg(result) => tracing::debug!(
                "Threshold CoordinateDkg RPC succeeded [id={} key_id={} alias={} status={}]",
                req_id,
                result.key_id,
                result.alias,
                result.status
            ),
        }
    }
}

#[derive(Clone)]
pub struct ThresholdService {
    client: ThresholdPluginClient<Channel>,
    groups: ThresholdGroupRegistry,
}

impl ThresholdService {
    pub fn new(client: ThresholdPluginClient<Channel>, groups: ThresholdGroupRegistry) -> Self {
        Self { client, groups }
    }

    pub fn validate_coordinate_dkg(req: &DkgRequest) -> Result<(), ThresholdError> {
        validate_required("Alias", &req.alias)?;
        validate_alias(&req.alias)?;
        validate_required("GroupName", &req.group_name)?;
        if req.group_name != req.group_name.trim() {
            return Err(ThresholdError::SurroundingWhitespace("group_name"));
        }
        validate_required("SessionId", &req.session_id)?;
        if req.session_id != req.session_id.trim() {
            return Err(ThresholdError::SurroundingWhitespace("session_id"));
        }
        Ok(())
    }

    pub async fn execute(
        &mut self,
        client_id: &str,
        req_id: u64,
        call: ThresholdRpcCall,
    ) -> Result<ThresholdRpcResult, tonic::Status> {
        call.log_start(req_id);

        let result = match call {
            ThresholdRpcCall::CoordinateDkg(req) => {
                ThresholdRpcResult::CoordinateDkg(self.coordinate_dkg(client_id, req).await?)
            }
        };

        result.log_success(req_id);
        Ok(result)
    }

    pub async fn coordinate_dkg(
        &mut self,
        client_id: &str,
        req: DkgRequest,
    ) -> Result<DkgResponse, tonic::Status> {
        let alias = req.alias.trim().to_string();
        let group_name = req.group_name;
        let session_id = req.session_id.trim().to_string();
        let group = self.groups.get(&group_name).ok_or_else(|| {
            tonic::Status::invalid_argument(format!(
                "Threshold group {group_name} is not configured"
            ))
        })?;

        let response: PluginDkgResponse = self
            .client
            .coordinate_dkg(tonic::Request::new(PluginDkgRequest {
                key_name: alias.clone(),
                group_name: group_name.clone(),
                session_id,
                threshold: group.threshold,
                participants: group
                    .participants
                    .into_iter()
                    .map(|node| PluginGroupMember {
                        node_id: node.node_id,
                        party_index: node.party_index,
                        openbao_url: node.openbao_url,
                        mount: if node.mount.trim().is_empty() {
                            "threshold".to_string()
                        } else {
                            node.mount
                        },
                    })
                    .collect(),
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        let status = aggregate_dkg_status(&response)?;
        Ok(DkgResponse {
            key_id: threshold_key_id(&alias),
            alias,
            group_name: response.group_name,
            status,
            public_key: response.public_key,
        })
    }
}

fn validate_group_config(name: &str, group: &ThresholdGroupConfig) -> Result<(), ThresholdError> {
    validate_required("GroupName", name)?;

    let participant_count = group.participants.len();
    if participant_count < 2 {
        return Err(ThresholdError::NotEnoughParticipants(name.to_string()));
    }
    if group.threshold < 2 || group.threshold as usize > participant_count {
        return Err(ThresholdError::ThresholdOutOfRange(name.to_string()));
    }

    let mut node_ids = HashSet::with_capacity(participant_count);
    let mut party_indexes = HashSet::with_capacity(participant_count);
    for participant in &group.participants {
        validate_required("NodeId", &participant.node_id)?;
        validate_required("OpenBaoUrl", &participant.openbao_url)?;
        if !node_ids.insert(participant.node_id.as_str()) {
            return Err(ThresholdError::DuplicateNodeId {
                group: name.to_string(),
                node_id: participant.node_id.clone(),
            });
        }
        if participant.party_index < 0 || participant.party_index as usize >= participant_count {
            return Err(ThresholdError::PartyIndexOutOfRange {
                node_id: participant.node_id.clone(),
                party_index: participant.party_index,
            });
        }
        if !party_indexes.insert(participant.party_index) {
            return Err(ThresholdError::DuplicatePartyIndex {
                group: name.to_string(),
                party_index: participant.party_index,
            });
        }
    }

    Ok(())
}

fn validate_required(field_name: &'static str, value: &str) -> Result<(), ThresholdError> {
    if value.trim().is_empty() {
        return Err(ThresholdError::MissingField(field_name));
    }
    Ok(())
}

fn validate_alias(value: &str) -> Result<(), ThresholdError> {
    if value != value.trim() {
        return Err(ThresholdError::SurroundingWhitespace("alias"));
    }
    if value.len() > MAX_ALIAS_LEN {
        return Err(ThresholdError::AliasTooLong(MAX_ALIAS_LEN));
    }
    if value.starts_with(KEY_ID_PREFIX) {
        return Err(ThresholdError::AliasReservedPrefix);
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
    {
        return Err(ThresholdError::AliasUnsupportedCharacters);
    }
    Ok(())
}

fn threshold_key_id(alias: &str) -> String {
    format!("{KEY_ID_PREFIX}{alias}")
}

fn aggregate_dkg_status(response: &PluginDkgResponse) -> Result<String, tonic::Status> {
    if response.nodes.is_empty() {
        return Err(tonic::Status::internal(
            "Threshold plugin returned no DKG node statuses",
        ));
    }

    for node in &response.nodes {
        if node.status != DKG_COMPLETED_STATUS {
            return Err(tonic::Status::internal(format!(
                "Threshold DKG node {} returned status {}",
                node.node_id, node.status
            )));
        }
    }

    Ok(DKG_COMPLETED_STATUS.to_string())
}

#[cfg(test)]
mod test {
    use super::*;

    fn valid_request() -> DkgRequest {
        DkgRequest {
            alias: "key-1".to_string(),
            group_name: "team-a".to_string(),
            session_id: "dkg-1".to_string(),
        }
    }

    #[test]
    fn validate_coordinate_dkg_accepts_alias_and_group() {
        let req = valid_request();
        ThresholdService::validate_coordinate_dkg(&req).unwrap();
    }

    #[test]
    fn threshold_group_registry_rejects_duplicate_party_index() {
        let err = ThresholdGroupRegistry::from_json(
            r#"{
                "team-a": {
                    "threshold": 2,
                    "participants": [
                        {"node_id": "node-a", "party_index": 0, "openbao_url": "http://node-a", "mount": "threshold"},
                        {"node_id": "node-b", "party_index": 1, "openbao_url": "http://node-b", "mount": "threshold"},
                        {"node_id": "node-c", "party_index": 1, "openbao_url": "http://node-c", "mount": "threshold"}
                    ]
                }
            }"#,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("duplicate participant party_index")
        );
    }

    #[test]
    fn validate_coordinate_dkg_rejects_invalid_alias() {
        let mut req = valid_request();
        req.alias = "invalid/key".to_string();

        let err = ThresholdService::validate_coordinate_dkg(&req).unwrap_err();
        assert!(
            err.to_string()
                .contains("alias contains unsupported characters")
        );
    }

    #[test]
    fn validate_coordinate_dkg_rejects_reserved_alias_prefix() {
        let mut req = valid_request();
        req.alias = "threshold:key-1".to_string();

        let err = ThresholdService::validate_coordinate_dkg(&req).unwrap_err();
        assert!(
            err.to_string()
                .contains("reserved threshold:<alias> format")
        );
    }

    #[test]
    fn validate_coordinate_dkg_rejects_missing_session_id() {
        let mut req = valid_request();
        req.session_id.clear();

        let err = ThresholdService::validate_coordinate_dkg(&req).unwrap_err();
        assert!(err.to_string().contains("SessionId is required"));
    }
}
