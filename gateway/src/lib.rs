// Include the `items` module, which is generated from items.proto.
// It is important to maintain the same structure as in the proto.
pub mod proto {
    // Plugin modules are enumerated at build time by `build.rs`:
    // one `pub mod <package>` per `.proto` under `proto/plugins/`.
    // Adding a new plugin requires no edits here.
    pub mod plugins {
        include!(concat!(env!("OUT_DIR"), "/_plugin_modules.rs"));
    }

    pub mod services {
        pub mod ctrng {
            tonic::include_proto!("ctrng");
        }
    }
}

pub mod types;

pub mod logging;
pub mod metrics;

pub mod filters;
pub mod plugins;
pub mod server;
pub mod service_manager;
pub mod services;
pub mod structures;
pub mod trng;
