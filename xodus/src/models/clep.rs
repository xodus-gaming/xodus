use zerocopy::{FromZeros, IntoBytes};

#[derive(FromZeros, IntoBytes)]
#[repr(C, packed)]
pub struct ClepV2 {
    pub version: u32,
    pub smbios: [u8; 256],
    pub disk_serial: [u8; 64],
    pub always_0: u32,
    pub always_1: bool,
    pub unused_tpm: [u8; 931],
    pub is_windows_to_go: bool,
    pub enscrowed_device_key: [u8; 148],
    pub reserved: [u8; 639],
}

#[derive(FromZeros, IntoBytes)]
#[repr(C, packed)]
pub struct ClepV4 {
    pub version: u32,
    pub smbios: [u8; 256],
    pub disk_serial: [u8; 64],
    pub tpm_status: bool,
    pub tpm_srk_public_area: [u8; 282],
    pub tpm_srk_public_area_reseved: [u8; 222],
    pub tpm_srk_certification_data: [u8; 141],
    pub tpm_srk_certification_signature: [u8; 256],
    pub is_windows_to_go: bool,
    pub debugger_enabled: u32,
    pub debuger_not_present: u32,
    pub enscrowed_device_key: [u8; 148],
    pub reserved: [u8; 665],
}
