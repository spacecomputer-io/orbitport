use std::io::Result;

fn build_plugins(proto_dir: &str) -> std::io::Result<()> {
    tonic_prost_build::configure()
        .build_server(false)
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(
            &["auth.proto", "ao.proto", "ipfs.proto", "masterseed.proto"],
            &[proto_dir], // specify the root location to search proto dependencies
        )
}

fn build_services(proto_dir: &str) -> std::io::Result<()> {
    tonic_prost_build::configure()
        .build_server(false)
        .protoc_arg("--experimental_allow_proto3_optional")
        // Add serde attributes to all generated message structs
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(
            &["ctrng.proto"],
            &[proto_dir], // specify the root location to search proto dependencies
        )
}

fn main() -> Result<()> {
    if let Err(_e) = build_plugins("../proto/plugins") {
        // trying from current directory if the first path doesn't work
        build_plugins("./proto/plugins").unwrap();
    }

    if let Err(_e) = build_services("../proto/services") {
        // trying from current directory if the first path doesn't work
        build_services("./proto/services").unwrap();
    }

    Ok(())
}
