//! Generic plugin dispatcher.
//!
//! Any plugin whose `.proto` is compiled into `proto/plugins/` is callable
//! via JSON-RPC with no per-plugin Rust code. The gateway keeps a descriptor
//! pool (baked in at build time from the FileDescriptorSet) and a dynamic
//! gRPC codec that transcodes JSON⇄proto at request time.
//!
//! JSON-RPC usage:
//! ```json
//! {
//!   "jsonrpc": "2.0",
//!   "id": 1,
//!   "method": "plugin.Call",
//!   "params": {
//!     "plugin": "masterseed",
//!     "method": "masterseed.MasterSeedPlugin.GetSeeds",
//!     "request": {"count": 2}
//!   }
//! }
//! ```

use std::str::FromStr;
use std::sync::OnceLock;

use bytes::{Buf, BufMut};
use http::uri::PathAndQuery;
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor};
use serde::Deserialize;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::{Request, Status, client::Grpc};

use crate::plugins::PluginCatalog;

/// Baked-in FileDescriptorSet for every plugin proto under `proto/plugins/`.
/// Emitted by `build.rs` when the `reflection` feature is enabled.
const PLUGIN_DESCRIPTOR_SET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/plugins.bin"));

fn pool() -> &'static DescriptorPool {
    static POOL: OnceLock<DescriptorPool> = OnceLock::new();
    POOL.get_or_init(|| {
        DescriptorPool::decode(PLUGIN_DESCRIPTOR_SET)
            .expect("plugin FileDescriptorSet is valid at build time")
    })
}

/// JSON-RPC params for the generic `plugin.Call` method.
#[derive(Deserialize, Debug)]
pub struct PluginCallRequest {
    /// Catalog key of the target plugin (e.g. `"masterseed"`) — must match
    /// an `ORBITPORT_PLUGIN_<NAME>` environment variable.
    pub plugin: String,
    /// Fully qualified gRPC method name: `package.Service.Method`.
    pub method: String,
    /// Method arguments as JSON, shaped like the proto request message.
    /// Optional — defaults to `{}` for empty-request methods.
    #[serde(default)]
    pub request: serde_json::Value,
}

pub async fn dispatch(
    catalog: &PluginCatalog,
    call: PluginCallRequest,
) -> Result<serde_json::Value, Status> {
    let (service_name, method_name) = call.method.rsplit_once('.').ok_or_else(|| {
        Status::invalid_argument("method must be fully qualified: package.Service.Method")
    })?;

    let service = pool().get_service_by_name(service_name).ok_or_else(|| {
        Status::not_found(format!("service '{service_name}' not in descriptor pool"))
    })?;
    let method = service
        .methods()
        .find(|m| m.name() == method_name)
        .ok_or_else(|| {
            Status::not_found(format!(
                "method '{method_name}' not found on service '{service_name}'"
            ))
        })?;

    let input_desc = method.input();
    let input_msg = {
        let json = serde_json::to_string(&call.request)
            .map_err(|e| Status::internal(format!("failed to stringify request params: {e}")))?;
        let mut de = serde_json::Deserializer::from_str(&json);
        DynamicMessage::deserialize(input_desc, &mut de)
            .map_err(|e| Status::invalid_argument(format!("request does not match schema: {e}")))?
    };

    let channel = catalog
        .get_client(&call.plugin)
        .await
        .map_err(|_| Status::unavailable(format!("plugin '{}' unavailable", call.plugin)))?;

    let path = PathAndQuery::from_str(&format!("/{service_name}/{method_name}"))
        .map_err(|e| Status::internal(format!("invalid gRPC path: {e}")))?;

    let codec = DynamicCodec {
        output_desc: method.output(),
    };
    let mut grpc = Grpc::new(channel);
    grpc.ready()
        .await
        .map_err(|e| Status::unavailable(format!("gRPC client not ready: {e}")))?;

    let response = grpc.unary(Request::new(input_msg), path, codec).await?;
    let msg = response.into_inner();
    serde_json::to_value(&msg)
        .map_err(|e| Status::internal(format!("failed to serialize response: {e}")))
}

/// Tonic codec that operates on `DynamicMessage`, parameterised by the
/// expected output descriptor so the decoder knows what shape to build.
#[derive(Clone)]
struct DynamicCodec {
    output_desc: MessageDescriptor,
}

impl Codec for DynamicCodec {
    type Encode = DynamicMessage;
    type Decode = DynamicMessage;
    type Encoder = DynamicEncoder;
    type Decoder = DynamicDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        DynamicEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        DynamicDecoder {
            desc: self.output_desc.clone(),
        }
    }
}

struct DynamicEncoder;

impl Encoder for DynamicEncoder {
    type Item = DynamicMessage;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        let mut buf = Vec::with_capacity(item.encoded_len());
        item.encode(&mut buf)
            .map_err(|e| Status::internal(format!("encode error: {e}")))?;
        dst.put_slice(&buf);
        Ok(())
    }
}

struct DynamicDecoder {
    desc: MessageDescriptor,
}

impl Decoder for DynamicDecoder {
    type Item = DynamicMessage;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        let bytes = src.copy_to_bytes(src.remaining());
        DynamicMessage::decode(self.desc.clone(), bytes)
            .map(Some)
            .map_err(|e| Status::internal(format!("decode error: {e}")))
    }
}
