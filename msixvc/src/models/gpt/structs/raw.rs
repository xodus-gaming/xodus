use zerocopy::{FromBytes, Immutable, IntoBytes, little_endian::*};

/// GPT Partition Table Header.
///
/// See <https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_table_header_(LBA_1)>.
#[derive(FromBytes, IntoBytes, Immutable, Debug)]
#[repr(C, packed)]
pub struct GptHeader {
    pub magic: [u8; 8],
    pub revision_number: U32,
    pub header_size: U32,
    pub checksum: U32,
    pub _reserved: U32,
    pub current_lba: U64,
    pub backup_lba: U64,
    pub first_partitions_lba: U64,
    pub last_partitions_lba: U64,
    pub disk_guid: [u8; 16],
    pub partition_table_lba: U64,
    pub partition_entries_num: U32,
    pub partition_entry_size: U32,
    pub partition_table_checksum: U32,
}

/// GPT Partition Table Entry.
///
/// See <https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_entries_(LBA_2%E2%80%9333)>.
#[derive(FromBytes, IntoBytes, Immutable, Debug)]
#[repr(C, packed)]
pub struct PartitionEntry {
    pub partition_type: [u8; 16],
    pub unique_partition: [u8; 16],
    pub first_lba: U64,
    pub last_lba: U64,
    pub attribute_flags: U64,
    pub partition_name: [U16; 0x24],
}
