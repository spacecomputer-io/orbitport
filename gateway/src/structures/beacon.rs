use serde::{Deserialize, Serialize};

use crate::structures::block::Block;
use crate::structures::service::ServiceResult;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconMetadata {
    pub name: String,
    pub version: String,
    pub desc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconGenesisBlockData {
    pub metadata: BeaconMetadata,
    pub pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconBlockData {
    pub sequence: u64,
    pub items: Vec<ServiceResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BeaconBlock {
    Genesis(BeaconGenesisBlockData),
    Block(BeaconBlockData),
}

impl BeaconBlock {
    pub fn is_genesis(&self) -> bool {
        matches!(self, BeaconBlock::Genesis(_))
    }

    pub fn is_block(&self) -> bool {
        matches!(self, BeaconBlock::Block(_))
    }

    pub fn new_genesis(metadata: BeaconMetadata, pubkey: String) -> Self {
        BeaconBlock::Genesis(BeaconGenesisBlockData { metadata, pubkey })
    }

    pub fn new_block(sequence: u64, items: Vec<ServiceResult>) -> Self {
        BeaconBlock::Block(BeaconBlockData { sequence, items })
    }
}

impl std::fmt::Display for BeaconBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BeaconBlock::Genesis(data) => write!(f, "Genesis Block: {:?}", data),
            BeaconBlock::Block(data) => write!(f, "Block: {:?}", data),
        }
    }
}

impl TryFrom<Vec<u8>> for BeaconBlock {
    type Error = serde_json::Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&bytes)
    }
}

impl TryFrom<BeaconBlock> for Vec<u8> {
    type Error = serde_json::Error;

    fn try_from(block: BeaconBlock) -> Result<Self, Self::Error> {
        serde_json::to_vec(&block)
    }
}

impl TryFrom<Block> for BeaconBlock {
    type Error = serde_json::Error;

    fn try_from(block: Block) -> Result<Self, Self::Error> {
        BeaconBlock::try_from(block.data)
    }
}

/// Converts a `BeaconBlock` to a `Block` by serializing it to JSON.
/// NOTE: 'link' should be set by the caller
impl TryFrom<BeaconBlock> for Block {
    type Error = serde_json::Error;

    fn try_from(block: BeaconBlock) -> Result<Self, Self::Error> {
        let data = Vec::try_from(block)?;
        let link = "".to_string();
        Ok(Block::new(link, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_beacon_genesis_block() {
        let metadata = BeaconMetadata {
            name: "Test Beacon".to_string(),
            version: "1.0".to_string(),
            desc: Some("Test description".to_string()),
        };
        let pubkey = "test_pubkey".to_string();
        let genesis_block = BeaconBlock::new_genesis(metadata.clone(), pubkey.clone());
        assert!(genesis_block.is_genesis());
        assert!(!genesis_block.is_block());

        let block = Block::try_from(genesis_block.clone()).unwrap();
        assert_eq!(block.link, "");
        assert_eq!(block.data, Vec::try_from(genesis_block.clone()).unwrap());
        if let BeaconBlock::Genesis(genesis_data) = genesis_block {
            assert_eq!(metadata.name, genesis_data.metadata.name);
        } else {
            panic!("Expected a Genesis block");
        }
    }
}
