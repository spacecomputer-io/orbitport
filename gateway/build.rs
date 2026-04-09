use std::io::Result;

fn main() -> Result<()> {
    // compiling plugin protos
    tonic_prost_build::configure()
        .build_server(false)
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(
            &[
                "auth.proto",
                "trng.proto",
                "ipfs.proto",
                "masterseed.proto",
            ],
            &["../proto/plugins"], // specify the root location to search proto dependencies
        )
        .unwrap();

    // compiling services protos
    tonic_prost_build::configure()
        .build_server(false)
        .protoc_arg("--experimental_allow_proto3_optional")
        // Add serde attributes to all generated message structs
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(
            &[
                "ctrng.proto",
            ],
            &["../proto/services"], // specify the root location to search proto dependencies
        )
        .unwrap();

    Ok(())
}
