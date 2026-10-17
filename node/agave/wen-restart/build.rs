use std::io::Result;

fn main() -> Result<()> {
    const PROTOC_ENVAR: &str = "PROTOC";
    if std::env::var(PROTOC_ENVAR).is_err() {
        std::env::set_var(
            PROTOC_ENVAR,
            protoc_bin_vendored::protoc_bin_path().expect("bundled protoc for this host"),
        );
    }

    let proto_base_path = std::path::PathBuf::from("proto");
    let proto = proto_base_path.join("wen_restart.proto");
    println!("cargo:rerun-if-changed={}", proto.display());

    // Generate rust files from protos.
    prost_build::compile_protos(&[proto], &[proto_base_path])?;
    Ok(())
}
