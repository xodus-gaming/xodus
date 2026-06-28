use crate::common::*;
use crate::models::xsp::{XspHeader, XspPatchRecord};
use tokio::{
    fs::OpenOptions,
    io::{AsyncSeekExt, BufReader},
};

pub struct XspFile {
    header: XspHeader,
    entries: Vec<XspPatchRecord>,
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
        let mut entries = Vec::with_capacity(header.record_count as usize);
        file.seek(std::io::SeekFrom::Start(header.page_size as u64))
            .await?;
        for _ in 0..header.record_count {
            let record = read_struct!(XspPatchRecord, file).unwrap();
            entries.push(record);
        }

        println!("{header:?}");
        println!("{entries:#?}");

        Ok(Self { header, entries })
    }
}
