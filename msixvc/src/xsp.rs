use crate::models::xsp::{XspHeader, XspPatchRecord};
use tokio::io::{AsyncRead, AsyncSeek};
use tokio::io::{AsyncSeekExt, BufReader};

pub struct XspFile {
    pub header: XspHeader,
    pub entries: Vec<XspPatchRecord>,
}

impl XspFile {
    pub async fn parse_file<Reader>(file: Reader) -> Result<Self, Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let mut file = BufReader::new(file);

        let header = XspHeader::read(&mut file).await?;
        let mut entries = Vec::with_capacity(header.record_count as usize);
        file.seek(std::io::SeekFrom::Start(header.page_size as u64))
            .await?;

        for _ in 0..header.record_count {
            let record = XspPatchRecord::read(&mut file).await?;
            entries.push(record);
        }

        Ok(Self { header, entries })
    }
}
