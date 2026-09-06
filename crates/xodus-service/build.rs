fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/");
    prost_build::compile_protos(&["proto/common.proto", "proto/xuser.proto"], &["proto"])?;
    Ok(())
}
