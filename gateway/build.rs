use std::io::Result;

const SERDE_DERIVES: &str = "#[derive(serde::Serialize, serde::Deserialize)]";
const SERDE_DEFAULT: &str = "#[serde(default)]";
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
    "kms.EncapsulateRequest",
    "kms.EncapsulateResponse",
    "kms.DecapsulateRequest",
    "kms.DecapsulateResponse",
    "kms.CreateKeyRequest",
    "kms.CreateKeyResponse",
    "kms.GenerateDataKeyRequest",
    "kms.GenerateDataKeyResponse",
    "kms.RotateKeyRequest",
    "kms.RotateKeyResponse",
    "kms.GetCapabilitiesRequest",
    "kms.GetCapabilitiesResponse",
    "kms.GetImportParametersRequest",
    "kms.GetImportParametersResponse",
    "kms.ImportKeyMaterialRequest",
    "kms.ImportKeyMaterialResponse",
    "kms.ImportKeyMaterialVersionRequest",
    "kms.ImportKeyMaterialVersionResponse",
    "kms.RegisterExportWrappingKeyRequest",
    "kms.RegisterExportWrappingKeyResponse",
    "kms.ExportKeyMaterialRequest",
    "kms.ExportKeyMaterialResponse",
    "kms.DeleteKeyRequest",
    "kms.DeleteKeyResponse",
    "kms.SigningCapability",
    "kms.KeyAgreementCapability",
    "kms.SchemeCapability",
];

const THRESHOLD_PASCAL_CASE_TYPES: &[&str] = &["threshold.DkgRequest", "threshold.DkgResponse"];

fn apply_service_attributes(config: tonic_prost_build::Builder) -> tonic_prost_build::Builder {
    let config = KMS_PASCAL_CASE_TYPES
        .iter()
        .chain(THRESHOLD_PASCAL_CASE_TYPES.iter())
        .fold(config, |config, ty| config.type_attribute(*ty, PASCAL_CASE));

    [
        "kms.KeyMetadata.origin",
        "kms.KeyMetadata.public_only",
        "kms.SchemeCapability.supports_get_import_parameters",
        "kms.SchemeCapability.supports_import_key_material",
        "kms.SchemeCapability.supports_import_key_material_version",
        "kms.SchemeCapability.supports_byok_export",
        "kms.SchemeCapability.supports_delete_key",
        "kms.SchemeCapability.import_hash_functions",
    ]
    .iter()
    .fold(config, |config, field| {
        config.field_attribute(*field, SERDE_DEFAULT)
    })
}

fn build_plugins(proto_dir: &str) -> Result<()> {
    let (_, plugin_protos) = protos_in_dir(proto_dir)?;

    // Enable server stubs only for protos that need to be mocked in
    // gateway-side integration tests. Today: account.
    tonic_prost_build::configure()
        .build_server(true)
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(
            &plugin_protos.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            &[proto_dir],
        )?;

    Ok(())
}

fn build_services(proto_dir: &str) -> Result<()> {
    let (_, service_protos) = protos_in_dir(proto_dir)?;

    let config = apply_service_attributes(
        tonic_prost_build::configure()
            .build_server(false)
            .protoc_arg("--experimental_allow_proto3_optional")
            // Add serde attributes to all generated message structs.
            .type_attribute(".", SERDE_DERIVES),
    );

    config.compile_protos(
        &service_protos
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>(),
        &[proto_dir],
    )?;

    Ok(())
}

fn main() -> Result<()> {
    if let Err(_e) = build_plugins("../proto/plugins") {
        build_plugins("./proto/plugins")?;
    }

    if let Err(_e) = build_services("../proto/services") {
        build_services("./proto/services")?;
    }

    Ok(())
}

fn protos_in_dir(dir: &str) -> Result<(String, Vec<String>)> {
    if !std::path::Path::new(dir).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Directory {dir} not found"),
        ));
    }

    let mut protos = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let (_, mut nested_protos) = protos_in_dir(entry.path().to_str().unwrap())?;
            protos.append(&mut nested_protos);
            continue;
        }

        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("proto") {
            protos.push(path.to_str().unwrap().to_string());
        }
    }

    Ok((dir.to_string(), protos))
}
