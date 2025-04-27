use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A block that contains data and a link to the next block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub link: String,
    pub data: Vec<u8>,
}

impl Block {
    /// Creates a new `Block` with the given link and data.
    pub fn new(link: String, data: Vec<u8>) -> Self {
        Block { link, data }
    }

    pub fn hash(&self) -> Option<String> {
        let mut hasher = Sha256::new();
        let block_bytes: Vec<u8> = match TryFrom::try_from(self.clone()) {
            Ok(bytes) => bytes,
            Err(_) => {
                tracing::warn!("Failed to convert block to raw data");
                return None;
            }
        };
        hasher.update(&block_bytes);
        let hash = hasher.finalize();
        Some(hex::encode(hash))
    }
}

/// Converts a `Block` to a string representation.
impl std::fmt::Display for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Block {{ link: {}, data: {} }}",
            self.link,
            hex::encode(&self.data)
        )
    }
}

/// Converts a `Block` from a `Vec<u8>` by deserializing it from JSON.
impl TryFrom<Vec<u8>> for Block {
    type Error = serde_json::Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&bytes)
    }
}

/// Converts a `Block` to a `Vec<u8>` by serializing it to JSON.
impl TryFrom<Block> for Vec<u8> {
    type Error = serde_json::Error;

    fn try_from(block: Block) -> Result<Self, Self::Error> {
        serde_json::to_vec(&block)
    }
}
