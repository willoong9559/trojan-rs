fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 只用 tonic_build，不用 tonic
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&["proto/trojan.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/trojan.proto");
    Ok(())
}
