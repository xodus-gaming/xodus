use crate::common::*;
use crate::models::xsp::XspHeader;
use tokio::{fs::OpenOptions, io::BufReader};

pub struct XspFile {
    header: XspHeader,
}
impl XspFile {
    pub async fn parse_file(path: String) -> Result<Self, Box<dyn std::error::Error>> {
        let file = OpenOptions::new()
            .read(true)
            .open(path.clone())
            .await
            .expect("Unable to open file");

        let mut file = BufReader::new(file);

        let header = read_struct!(XspHeader, file)?;

        Ok(Self { header })
    }
}
