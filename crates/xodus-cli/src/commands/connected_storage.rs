use serde_core::ser::Serialize;
use std::io::Read;
use std::{fs::File, io::Write, process::ExitCode};
use xodus::api::xbox::upload_connected_storage_xml;
use xodus::models::xbox::XbConnectedStorageSpace;
use xodus::{api::xbox::download_connected_storage_xml, tokens::TokenManager};

pub struct ConnectedStorageIdentity<'a> {
    pub msa_id: &'a str,
    pub title_id: i64,
    pub pfn: &'a str,
    pub file: &'a str,
    pub scid: Option<&'a str>,
}

pub async fn download(
    client: &reqwest::Client,
    tokens: &TokenManager,
    identity: &ConnectedStorageIdentity<'_>,
) -> ExitCode {
    let mut file = File::create(identity.file).unwrap();
    let data = download_connected_storage_xml(
        client,
        tokens,
        identity.msa_id,
        identity.title_id,
        identity.pfn,
        identity.scid,
    )
    .await
    .unwrap();
    let mut writer = String::new();
    let mut ser = quick_xml::se::Serializer::new(&mut writer);
    ser.text_format(quick_xml::se::TextFormat::CData);
    data.serialize(ser).unwrap();
    file.write_all(writer.as_bytes()).unwrap();
    ExitCode::SUCCESS
}

pub async fn upload(
    client: &reqwest::Client,
    tokens: &TokenManager,
    identity: &ConnectedStorageIdentity<'_>,
    keep_existing: bool,
) -> ExitCode {
    let mut file = File::open(identity.file).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    let storage: XbConnectedStorageSpace = quick_xml::de::from_str(&content).unwrap();
    upload_connected_storage_xml(
        client,
        tokens,
        identity.msa_id,
        identity.title_id,
        identity.pfn,
        identity.scid,
        storage,
        keep_existing,
    )
    .await
    .unwrap();
    ExitCode::SUCCESS
}
