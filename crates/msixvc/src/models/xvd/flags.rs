use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct XvdVolumeFlags: u32 {
        const READ_ONLY = 1 << 0;
        const ENCRYPTION_DISABLED = 1 << 1;
        const DATA_INTEGRITY_DISABLED = 1 << 2;
        const LEGACY_SECTOR_SIZE = 1 << 3;
        const RESILIENCY_ENABLED = 1 << 4;
        const SRA_READ_ONLY = 1 << 5;
        const REGION_ID_IN_XTS = 1 << 6;
        const ERA_SPECIFIC = 1 << 7;
    }
}

impl XvdVolumeFlags {
    pub fn is_encrypted(&self) -> bool {
        !self.contains(Self::ENCRYPTION_DISABLED)
    }

    pub fn is_legacy_sector_size(&self) -> bool {
        self.contains(Self::LEGACY_SECTOR_SIZE)
    }

    pub fn is_data_integrity_enabled(&self) -> bool {
        !self.contains(Self::DATA_INTEGRITY_DISABLED)
    }

    pub fn is_resiliency_enabled(&self) -> bool {
        self.contains(Self::RESILIENCY_ENABLED)
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct WriteablePolicyFlags: u32 {}
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct XvcInfoFlags: u32 {}
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct XvcRegionFlags: u32 {
        const RESIDENT = 1 << 0;
        const INITIAL_PLAY = 1 << 1;
        const PREVIEW = 1 << 2;
        const FILE_SYSTEM_METADATA = 1 << 3;
        const PRESENT = 1 << 4;
        const ON_DEMAND = 1 << 5;
        const AVAILABLE = 1 << 6;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct XvcRegionPresenceInfoFlags: u8 {
        const IS_PRESENT = 1 << 0;
        const IS_AVAILABLE = 1 << 1;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct XvdSegmentMetadataSegmentFlags: u16 {
        const KEEP_ENCRYPTED_ON_DISK = 1;
    }
}
