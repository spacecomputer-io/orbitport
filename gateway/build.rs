use std::io::Result;

fn main() -> Result<()> {
    let (plugin_dir, plugin_protos) = protos_in_dir("../proto/plugins").or_else(|_| protos_in_dir("./proto/plugins"))?;

    tonic_prost_build::configure()
        .build_server(false)
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(
            &plugin_protos.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            &[&plugin_dir],
        )?;

    let (service_dir, service_protos) = protos_in_dir("../proto/services").or_else(|_| protos_in_dir("./proto/services"))?;
    tonic_prost_build::configure()
        .build_server(false)
        .protoc_arg("--experimental_allow_proto3_optional")
        // Add serde attributes to all generated message structs
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(
            &service_protos.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            &[&service_dir],
        )?;

    Ok(())
}

fn protos_in_dir(dir: &str) -> Result<(String, Vec<String>)> {
    // if not exist return error
    if !std::path::Path::new(dir).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Directory {} not found", dir),
        ));
    }
    let mut protos = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let (_, mut nested_protos) = protos_in_dir(&entry.path().to_str().unwrap())?;
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
