#[repr(u32)]
pub enum XvdVolumeFlags {
    ReadOnly = 1,
    EncryptionDisabled = 2,
    DataIntegrityDisabled = 4,
    LegacySectorSize = 8,
    ResiliencyEnabled = 0x10,
    SraReadOnly = 0x20,
    RegionIdInXts = 0x40,
    EraSpecific = 0x80,
}

#[repr(u32)]
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

#[repr(u32)]
pub enum XvcRegionFlags {
    Resident = 1,
    InitialPlay = 2,
    Preview = 4,
    FileSystemMetadata = 8,
    Present = 0x10,
    OnDemand = 0x20,
    Available = 0x40,
}

#[repr(u8)]
pub enum XvcRegionPresenceInfo {
    IsPresent = 1,   // not set = "not present"
    IsAvailable = 2, // not set = "unavailable"

    //value >> 4 = discnum
    Disc1 = 0x10,
    Disc2 = 0x20,
    Disc3 = 0x30,
    Disc4 = 0x40,
    Disc5 = 0x50,
    Disc6 = 0x60,
    Disc7 = 0x70,
    Disc8 = 0x80,
    Disc9 = 0x90,
    Disc10 = 0xA0,
    Disc11 = 0xB0,
    Disc12 = 0xC0,
    Disc13 = 0xD0,
    Disc14 = 0xE0,
    Disc15 = 0xF0,
}

#[repr(u16)]
pub enum XvdSegmentMetadataSegmentFlags {
    KeepEncryptedOnDisk = 1,
}

pub enum XvcRegionId {
    MetadataXvc = 0x40000001,
    MetadataFilesystem = 0x40000002,
    Unknown = 0x40000003,
    EmbeddedXvd = 0x40000004,
    Header = 0x40000005,
    MutableData = 0x40000006,
}
