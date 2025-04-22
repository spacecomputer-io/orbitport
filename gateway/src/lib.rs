// Include the `items` module, which is generated from items.proto.
// It is important to maintain the same structure as in the proto.
pub mod proto {
    pub mod auth {
        tonic::include_proto!("auth");
    }
    pub mod trng {
        tonic::include_proto!("trng");
    }
}

pub mod ctx;
pub mod logging;
pub mod os_signals;

pub mod metrics;

pub mod server;
pub mod service;
pub mod service_manager;
pub mod trng;
