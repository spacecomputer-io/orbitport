// Include the `items` module, which is generated from items.proto.
// It is important to maintain the same structure as in the proto.
pub mod proto {
    pub mod auth {
        tonic::include_proto!("auth");
    }
    pub mod trng {
        tonic::include_proto!("trng");
    }
    pub mod ipfs {
        tonic::include_proto!("ipfs");
    }
    pub mod masterseed {
        tonic::include_proto!("masterseed");
    }
}

pub mod types;

pub mod ctx;
pub mod logging;
pub mod os_signals;

pub mod metrics;
pub mod server;
pub mod service_manager;
pub mod structures;
pub mod trng;
