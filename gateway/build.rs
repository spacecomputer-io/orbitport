use std::io::Result;
use std::path::{Path, PathBuf};

/// Discover all `*.proto` files in a directory, returning their filenames
/// (not full paths) sorted for deterministic output.
fn discover_protos(proto_dir: &Path) -> std::io::Result<Vec<String>> {
    let mut protos = Vec::new();
    for entry in std::fs::read_dir(proto_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("proto")
            && let Some(name) = path.file_name().and_then(|s| s.to_str())
        {
            protos.push(name.to_string());
        }
    }
    protos.sort();
    Ok(protos)
}

/// Extract the `package X;` declaration from a proto file.
fn read_package(proto_path: &Path) -> std::io::Result<Option<String>> {
    let content = std::fs::read_to_string(proto_path)?;
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("package ") {
            let pkg = rest.trim_end_matches(';').trim();
            return Ok(Some(pkg.to_string()));
        }
    }
    Ok(None)
}

fn build_plugins(proto_dir: &str, out_dir: &Path) -> std::io::Result<()> {
    let dir = Path::new(proto_dir);
    let protos = discover_protos(dir)?;

    // Emit a module tree for lib.rs to include: one submodule per proto package.
    let mut modules = String::new();
    for proto in &protos {
        let proto_path = dir.join(proto);
        if let Some(pkg) = read_package(&proto_path)? {
            modules.push_str(&format!(
                "pub mod {pkg} {{ tonic::include_proto!(\"{pkg}\"); }}\n",
            ));
        }
    }
    std::fs::write(out_dir.join("_plugin_modules.rs"), modules)?;

    // Re-run this script when the proto directory changes (new plugin protos
    // should trigger regeneration of the module tree and descriptor set).
    println!("cargo:rerun-if-changed={proto_dir}");

    tonic_prost_build::configure()
        .build_server(false)
        .protoc_arg("--experimental_allow_proto3_optional")
        // Attach serde derives to every plugin message so the JSON-RPC
        // generic dispatcher can (de)serialize any plugin type.
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        // Emit a FileDescriptorSet so the gateway can look up service and
        // message descriptors at runtime for dynamic dispatch.
        .file_descriptor_set_path(out_dir.join("plugins.bin"))
        .compile_protos(&protos, &[proto_dir.to_string()])
}

fn build_services(proto_dir: &str) -> std::io::Result<()> {
    tonic_prost_build::configure()
        .build_server(false)
        .protoc_arg("--experimental_allow_proto3_optional")
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(
            &["ctrng.proto".to_string()],
            &[proto_dir.to_string()],
        )
}

fn resolve(candidates: &[&str]) -> String {
    for c in candidates {
        if Path::new(c).exists() {
            return (*c).to_string();
        }
    }
    panic!("none of the candidate proto dirs exist: {candidates:?}");
}

fn main() -> Result<()> {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    let plugins_dir = resolve(&["../proto/plugins", "./proto/plugins"]);
    build_plugins(&plugins_dir, &out_dir)?;

    let services_dir = resolve(&["../proto/services", "./proto/services"]);
    build_services(&services_dir)?;

    Ok(())
}
