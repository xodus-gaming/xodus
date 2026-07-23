use super::raw;

use std::range::RangeInclusive;

use uuid::Uuid;
use zerocopy::IntoBytes;

/// GPT Partition Table Header.
#[derive(Debug, Clone, Copy)]
pub struct GptHeader {
    /// Revision number of header.
    pub revision_number: u32,
    /// Current LBA (location of this header copy).
    pub current_lba: u64,
    /// Backup LBA (location of the other header copy).
    pub backup_lba: u64,
    /// Usable LBA range for partitions (`start` = primary partition table's last LBA + 1,
    /// `last` = secondary partition table's first LBA − 1, inclusive).
    pub partitions_lba: RangeInclusive<u64>,
    /// Disk GUID in little endian.
    pub disk_guid: Uuid,
    /// Starting LBA of array of partition entries.
    pub partition_table_lba: u64,
    /// Number of partition entries in array.
    pub partition_entries_num: usize,
    /// Size of a single partition entry (usually 80h or 128).
    pub partition_entry_size: usize,
    /// CRC-32 of partition entries array in little endian.
    pub partition_table_checksum: u32,
}

impl GptHeader {
    const MAGIC: [u8; 8] = *b"EFI PART";
    // Technically the header size can be higher, but this way the checksum can be
    // computed over a fixed-size struct.
    const EXPECTED_HEADER_SIZE: u32 = GptHeader::RAW_SIZE as u32;
    // The partition table must start at LBA 2 at the earliest: LBA 0 is reserved,
    // and LBA 1 is where the GPT header lives.
    const MIN_PARTITION_TABLE_LBA: u64 = 2;
    // The GPT spec defines that the partition table must exist, so the minimum number
    // of partition entries is 1. Also, to avoid OOM when reading malformed data, set
    // a reasonable maximum to the number of partition entries.
    const PARTITION_ENTRIES_NUM_RANGE: RangeInclusive<u32> = RangeInclusive {
        start: 1,
        last: 128,
    };
    /// In practice always 128 bytes, but the spec allows larger. The upper bound here is
    /// just a reasonable maximum, not a spec requirement.
    const PARTITION_ENTRY_SIZE_RANGE: RangeInclusive<u32> = RangeInclusive {
        start: PartitionEntry::RAW_SIZE as u32,
        last: 512,
    };
}

#[derive(thiserror::Error, Debug)]
pub enum GptHeaderParseError {
    #[error(r#"invalid magic: expected {magic:?}, got {0:?}"#, magic = GptHeader::MAGIC)]
    InvalidMagic([u8; 8]),

    #[error(r#"invalid header size: expected {size:?}, got {0:?}"#, size = GptHeader::EXPECTED_HEADER_SIZE)]
    InvalidHeaderSize(u32),

    #[error(r#"invalid crc32 checksum: computed {computed:x}, but header stores {stored:x}"#)]
    InvalidChecksum { computed: u32, stored: u32 },

    #[error("invalid starting LBA of array of partition table: expected at least {min}, got {0}", min = GptHeader::MIN_PARTITION_TABLE_LBA)]
    PartitionTableLbaTooShort(u64),

    #[error("invalid partition entries number: expected in range {min:?}, got {0}", min = GptHeader::PARTITION_ENTRIES_NUM_RANGE)]
    OobPartitionEntriesNum(u32),

    #[error("invalid partition entry size: expected in range {min:?}, got {0}", min = GptHeader::PARTITION_ENTRY_SIZE_RANGE)]
    OobPartitionEntrySize(u32),
}

impl TryFrom<raw::GptHeader> for GptHeader {
    type Error = GptHeaderParseError;

    fn try_from(mut value: raw::GptHeader) -> Result<Self, Self::Error> {
        if value.magic != Self::MAGIC {
            return Err(GptHeaderParseError::InvalidMagic(value.magic));
        }

        if value.header_size != Self::EXPECTED_HEADER_SIZE {
            return Err(GptHeaderParseError::InvalidHeaderSize(
                value.header_size.get(),
            ));
        }

        // Check the CRC32 hash of the header
        {
            let stored = value.checksum.get();

            // Clear the checksum field before hashing
            value.checksum = 0.into();

            let computed = crc32fast::hash(value.as_bytes());

            if computed != stored {
                return Err(GptHeaderParseError::InvalidChecksum { computed, stored });
            }
        }

        if value.partition_table_lba < Self::MIN_PARTITION_TABLE_LBA {
            return Err(GptHeaderParseError::PartitionTableLbaTooShort(
                value.partition_table_lba.get(),
            ));
        }

        if !Self::PARTITION_ENTRIES_NUM_RANGE.contains(&value.partition_entries_num.get()) {
            return Err(GptHeaderParseError::OobPartitionEntriesNum(
                value.partition_entries_num.get(),
            ));
        }

        if !Self::PARTITION_ENTRY_SIZE_RANGE.contains(&value.partition_entry_size.get()) {
            return Err(GptHeaderParseError::OobPartitionEntrySize(
                value.partition_entry_size.get(),
            ));
        }

        Ok(Self {
            revision_number: value.revision_number.get(),
            current_lba: value.current_lba.get(),
            backup_lba: value.backup_lba.get(),
            partitions_lba: RangeInclusive {
                start: value.first_partitions_lba.get(),
                last: value.last_partitions_lba.get(),
            },
            disk_guid: Uuid::from_bytes_le(value.disk_guid),
            partition_table_lba: value.partition_table_lba.get(),
            partition_entries_num: value.partition_entries_num.get() as usize,
            partition_entry_size: value.partition_entry_size.get() as usize,
            partition_table_checksum: value.partition_table_checksum.get(),
        })
    }
}

/// GPT Partition Table Entry.
#[derive(Debug, Clone, Copy)]
pub struct PartitionEntry {
    /// Partition type GUID.
    pub partition_type: Uuid,
    /// Unique partition GUID.
    pub unique_partition: Uuid,
    /// LBA range occupied by this partition, inclusive (end is usually odd).
    pub lba_range: RangeInclusive<u64>,
    /// Attribute flags.
    pub attribute_flags: u64,
    /// Partition name (36 UTF-16LE code units).
    pub partition_name: [u16; 0x24],
}

impl From<raw::PartitionEntry> for PartitionEntry {
    fn from(value: raw::PartitionEntry) -> Self {
        Self {
            partition_type: Uuid::from_bytes_le(value.partition_type),
            unique_partition: Uuid::from_bytes_le(value.unique_partition),
            lba_range: RangeInclusive {
                start: value.first_lba.get(),
                last: value.last_lba.get(),
            },
            attribute_flags: value.attribute_flags.get(),
            partition_name: value.partition_name.map(|n| n.get()),
        }
    }
}

impl PartitionEntry {
    pub fn partition_name(&self) -> String {
        let len = self
            .partition_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.partition_name.len());

        String::from_utf16_lossy(&self.partition_name[..len])
    }
}
