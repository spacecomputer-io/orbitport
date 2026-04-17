use std::io::Result;
use std::path::{Path, PathBuf};

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
    "kms.GetCapabilitiesRequest",
    "kms.GetCapabilitiesResponse",
    "kms.SigningCapability",
    "kms.SchemeCapability",
];

fn apply_kms_service_attributes(config: tonic_prost_build::Builder) -> tonic_prost_build::Builder {
    KMS_PASCAL_CASE_TYPES
        .iter()
        .fold(config, |config, ty| config.type_attribute(*ty, PASCAL_CASE))
}

fn build_plugins(proto_dir: &str) -> Result<()> {
    let (plugin_dir, plugin_protos) = protos_in_dir(proto_dir)?;

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    emit_plugin_modules(&plugin_dir, &out_dir)?;

    let reflection = std::env::var_os("CARGO_FEATURE_REFLECTION").is_some();

    let mut plugins_build = tonic_prost_build::configure()
        .build_server(false)
        .protoc_arg("--experimental_allow_proto3_optional");

    if reflection {
        // Emit a FileDescriptorSet so the gateway can resolve plugin service
        // and message descriptors at runtime for generic JSON-RPC dispatch.
        plugins_build = plugins_build.file_descriptor_set_path(out_dir.join("plugins.bin"));
        // Serde derives let dynamic messages round-trip through JSON-RPC.
        plugins_build = plugins_build.type_attribute(".", SERDE_DERIVES);
    }

    plugins_build.compile_protos(
        &plugin_protos.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        &[&plugin_dir],
    )?;

    Ok(())
}

fn build_services(proto_dir: &str) -> Result<()> {
    let (_, service_protos) = protos_in_dir(proto_dir)?;

    let config = apply_kms_service_attributes(
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

    println!("cargo:rerun-if-changed=../proto/plugins");
    println!("cargo:rerun-if-changed=../proto/services");

    Ok(())
}

fn protos_in_dir(dir: &str) -> Result<(String, Vec<String>)> {
    if !Path::new(dir).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Directory {} not found", dir),
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

/// Emit `_plugin_modules.rs` into OUT_DIR with one `pub mod <pkg> {
/// tonic::include_proto!("<pkg>"); }` per plugin proto package, so `lib.rs`
/// can include the module tree without per-plugin hand edits.
fn emit_plugin_modules(plugin_dir: &str, out_dir: &Path) -> Result<()> {
    let mut modules = String::new();
    let mut seen = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(plugin_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("proto") {
            continue;
        }
        if let Some(pkg) = read_package(&path)?
            && seen.insert(pkg.clone())
        {
            modules.push_str(&format!(
                "pub mod {pkg} {{ tonic::include_proto!(\"{pkg}\"); }}\n",
            ));
        }
    }
    std::fs::write(out_dir.join("_plugin_modules.rs"), modules)?;
    Ok(())
}

fn read_package(proto_path: &Path) -> Result<Option<String>> {
    let content = std::fs::read_to_string(proto_path)?;
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("package ") {
            return Ok(Some(rest.trim_end_matches(';').trim().to_string()));
        }
    }
    Ok(None)
}
