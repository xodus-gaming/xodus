use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum XvdType {
    Fixed = 0,
    Dynamic = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum XvdContentType {
    Data = 0,
    Title = 1,
    SystemOS = 2,
    EraOS = 3,
    Scratch = 4,
    ResetData = 5,
    Application = 6,
    HostOS = 7,
    X360STFS = 8,
    X360FATX = 9,
    X360GDFX = 0xA,
    Updater = 0xB,
    OfflineUpdater = 0xC,
    Template = 0xD,
    MteHost = 0xE,
    MteApp = 0xF,
    MteTitle = 0x10,
    MteEraOS = 0x11,
    EraTools = 0x12,
    SystemTools = 0x13,
    SystemAux = 0x14,
    AcousticModel = 0x15,
    SystemCodecsVolume = 0x16,
    QasltPackage = 0x17,
    AppDlc = 0x18,
    TitleDlc = 0x19,
    UniversalDlc = 0x1A,
    SystemDataVolume = 0x1B,
    TestVolume = 0x1C,
    HardwareTestVolume = 0x1D,
    KioskContent = 0x1E,
    HostProfiler = 0x20,
    Uwa = 0x21,
    Unknown22 = 0x22,
    Unknown23 = 0x23,
    Unknown24 = 0x24,
    ServerAgent = 0x25,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum XvcRegionId {
    MetadataXvc = 0x40000001,
    MetadataFilesystem = 0x40000002,
    Unknown = 0x40000003,
    EmbeddedXvd = 0x40000004,
    Header = 0x40000005,
    MutableData = 0x40000006,
    #[num_enum(catch_all)]
    Other(u32),
}
