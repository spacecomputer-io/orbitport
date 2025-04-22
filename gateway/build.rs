use std::io::Result;

fn main() -> Result<()> {
    // compiling protobuf files
    tonic_build::configure()
        .build_server(false)
        .compile_protos(
            &["proto/auth.proto", "proto/trng.proto"],
            &["proto"], // specify the root location to search proto dependencies
        )
        .unwrap();
    Ok(())
}
