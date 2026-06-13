use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(&["../proto/xodus.gamingservices.proto"], &["../proto"])?;
    Ok(())
}