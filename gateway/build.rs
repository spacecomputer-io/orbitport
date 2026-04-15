use std::io::Result;

const SERDE_DERIVES: &str = "#[derive(serde::Serialize, serde::Deserialize)]";
const PASCAL_CASE: &str = "#[serde(rename_all = \"PascalCase\")]";
const KMS_PASCAL_CASE_TYPES: &[&str] = &[
    "kms.Tag",
    "kms.KeyMetadata",
    "kms.EncryptRequest",
    "kms.EncryptResponse",
    "kms.DecryptRequest",
    "kms.DecryptResponse",
    "kms.SignRequest",
    "kms.SignResponse",
    "kms.CreateKeyRequest",
    "kms.CreateKeyResponse",
    "kms.GenerateDataKeyRequest",
    "kms.GenerateDataKeyResponse",
    "kms.RotateKeyRequest",
    "kms.RotateKeyResponse",
];

fn apply_kms_service_attributes(config: tonic_prost_build::Builder) -> tonic_prost_build::Builder {
    KMS_PASCAL_CASE_TYPES
        .iter()
        .fold(config, |config, ty| config.type_attribute(*ty, PASCAL_CASE))
}

fn build_plugins(proto_dir: &str) -> std::io::Result<()> {
    tonic_prost_build::configure()
        .build_server(false)
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(
            &[
                "auth.proto",
                "ao.proto",
                "ipfs.proto",
                "kms.proto",
                "masterseed.proto",
            ],
            &[proto_dir], // specify the root location to search proto dependencies
        )
}

fn build_services(proto_dir: &str) -> std::io::Result<()> {
    let config = apply_kms_service_attributes(
        tonic_prost_build::configure()
            .build_server(false)
            .protoc_arg("--experimental_allow_proto3_optional")
            // Add serde attributes to all generated message structs.
            .type_attribute(".", SERDE_DERIVES),
    );

    config.compile_protos(
        &["ctrng.proto", "kms.proto"],
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
