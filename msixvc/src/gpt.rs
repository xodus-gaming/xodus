//! Read-only, sequential parser for GUID Partition Table (GPT) disks.
//!
//! This module reads a GPT-partitioned disk asynchronously without
//! seeking from an [`AsyncRead`] stream and produces a [`GptDisk`]
//! containing the parsed header and partition entries.
//!
//! Only the **primary** GPT header and partition table (at the start of the
//! disk) are read. The backup copy at the end of the disk is never consulted.

use crate::models::gpt::*;
use crate::models::xvd::flags::XvdVolumeFlags;

use std::range::{Range, RangeInclusive};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
pub enum LogicalBlockSize {
    B4096,
    B512,
}

impl LogicalBlockSize {
    const fn get(self) -> usize {
        match self {
            Self::B4096 => 4096,
            Self::B512 => 512,
        }
    }
}

impl From<XvdVolumeFlags> for LogicalBlockSize {
    fn from(flags: XvdVolumeFlags) -> Self {
        if flags.contains(XvdVolumeFlags::LEGACY_SECTOR_SIZE) {
            Self::B512
        } else {
            Self::B4096
        }
    }
}

#[derive(Clone, Debug)]
pub struct GptDisk {
    logical_block_size: LogicalBlockSize,
    header: GptHeader,
    partitions: Vec<PartitionEntry>,
}

#[derive(Debug, Error)]
pub enum GptParseError {
    #[error("IO error: {0}")]
    IoError(#[from] tokio::io::Error),

    #[error("header: {0}")]
    InvalidHeader(#[from] GptHeaderParseError),

    #[error(
        "partition table: invalid crc32 checksum: computed {computed:x}, but header stores {stored:x}"
    )]
    InvalidPartitionTableChecksum { computed: u32, stored: u32 },

    #[error(
        "partition table: entry {partition_index}: invalid partition LBA range: expected in range {header_partitions_lba:?}, got {partition_lba_range:?}"
    )]
    OobPartitionEntryLba {
        partition_index: usize,
        header_partitions_lba: RangeInclusive<u64>,
        partition_lba_range: RangeInclusive<u64>,
    },

    #[error(
        "header: invalid first partitions LBA: {first_partitions_lba}, but partition table ends at LBA {partition_table_end}"
    )]
    InvalidFirstPartitionsLba {
        first_partitions_lba: u64,
        partition_table_end: u64,
    },

    #[error("partition with type GUID {0} not found")]
    MissingPartition(Uuid),
}

impl GptDisk {
    /// Read a primary GPT header and partition table asynchronously.
    ///
    /// The reader must be placed at the start of the GPT disk (LBA 0). After this function
    /// returns, the reader will be positioned at the beginning of the data for the first partition
    /// (after the partition table). No seeks will be performed.
    async fn read<R: AsyncRead + Unpin>(
        mut reader: R,
        logical_block_size: impl Into<LogicalBlockSize>,
    ) -> Result<GptDisk, GptParseError> {
        let logical_block_size = logical_block_size.into();
        let mut block = vec![0u8; logical_block_size.get()];

        // The first LBA is reserved for backwards-compatibility reasons.
        reader.read_exact(&mut block).await?;

        // The main GPT header is placed at LBA 1.
        reader.read_exact(&mut block).await?;

        let header = GptHeader::from_slice(&block)?;

        // Skip empty LBAs until the partition table.
        // Two LBAs have already been read, the first (reserved) one, and the GPT header.
        for _ in 2..header.partition_table_lba {
            reader.read_exact(&mut block).await?;
        }

        let table_size = header.partition_entries_num * header.partition_entry_size;
        let table_blocks = table_size.div_ceil(logical_block_size.get());
        let first_lba_after_partition_table = table_blocks as u64 + header.partition_table_lba;

        // Check that the beginning of the data for the first partition doesn't overlap the partition table.
        if header.partitions_lba.start < first_lba_after_partition_table {
            return Err(GptParseError::InvalidFirstPartitionsLba {
                first_partitions_lba: header.partitions_lba.start,
                partition_table_end: first_lba_after_partition_table - 1,
            });
        }

        // Read the partition table as a bytes Vec to be able to calculate the checksum.
        let table_bytes = {
            // Read the partition table as a whole number of logical blocks to keep the reader aligned.
            let mut table_padded = vec![0u8; table_blocks * logical_block_size.get()];
            reader.read_exact(&mut table_padded).await?;

            // Trim the padding.
            table_padded.truncate(table_size);
            table_padded
        };

        // Verify that the partition table checksum stored in the header is correct.
        {
            let stored = header.partition_table_checksum;
            let computed = crc32fast::hash(&table_bytes);

            if computed != stored {
                return Err(GptParseError::InvalidPartitionTableChecksum { computed, stored });
            }
        }

        // Push every partition entry into the partition entries Vec.
        let mut partitions = Vec::with_capacity(header.partition_entries_num);

        for (partition_index, entry) in table_bytes
            .chunks_exact(header.partition_entry_size)
            .enumerate()
        {
            let Ok(entry) = PartitionEntry::from_slice(entry);

            if entry.partition_type == Uuid::nil() {
                continue;
            }

            // Verify that the partition LBA range falls into the usable LBAs as designed by the header.
            if !header.partitions_lba.contains(&entry.lba_range.start)
                || !header.partitions_lba.contains(&entry.lba_range.last)
            {
                return Err(GptParseError::OobPartitionEntryLba {
                    partition_index,
                    header_partitions_lba: header.partitions_lba,
                    partition_lba_range: entry.lba_range,
                });
            }

            partitions.push(entry);
        }

        // The partition table has been read. Now, skip to the beginning of the data for the first partition.
        for _ in first_lba_after_partition_table..header.partitions_lba.start {
            reader.read_exact(&mut block).await?;
        }

        Ok(GptDisk {
            logical_block_size,
            header,
            partitions,
        })
    }
}

impl GptDisk {
    /// Finds the first partition with the provided type in the partition table.
    fn find_partition(&self, partition_type: Uuid) -> Option<&PartitionEntry> {
        self.partitions
            .iter()
            .find(|&part| part.partition_type == partition_type)
    }
}

impl GptDisk {
    /// Positions the given reader at the start of the partition.
    /// The provided reader must be placed at the start of the LBA range
    /// designed for partition data.
    async fn goto_partition<R: AsyncRead + Unpin>(
        &self,
        mut reader: R,
        partition: &PartitionEntry,
    ) -> Result<(), tokio::io::Error> {
        // Return fast if the position is already correct.
        if self.header.partitions_lba.start == partition.lba_range.start {
            return Ok(());
        }

        let mut block = vec![0u8; self.logical_block_size.get()];

        // Skip blocks from the start of the partitions LBA to the start of the given partition LBA
        for _ in self.header.partitions_lba.start..partition.lba_range.start {
            reader.read_exact(&mut block).await?;
        }

        Ok(())
    }
}

pub async fn goto_windows_basic_data_partition<R: AsyncRead + Unpin>(
    mut reader: R,
    logical_block_size: impl Into<LogicalBlockSize>,
) -> Result<Range<u64>, GptParseError> {
    // Read the Primary GPT Header.
    // The seek is now placed at the start of the partition data.
    let disk = GptDisk::read(&mut reader, logical_block_size).await?;

    // Find the first Windows Basic Data Partition. The XVC drive should have a single partition
    // of this type, but it is not checked for forward-compatibility reasons. If more than one partition
    // is found, return the first one which has the correct partition type.
    const WINDOWS_BASIC_DATA_PARTITION: Uuid = uuid::uuid!("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7");
    let basic_data_partition = disk.find_partition(WINDOWS_BASIC_DATA_PARTITION).ok_or(
        GptParseError::MissingPartition(WINDOWS_BASIC_DATA_PARTITION),
    )?;

    // Move the reader position to the start of the data partition. In practice, the data partition
    // is the only one, so this does nothing. However, it will work correctly if a partition
    // which is not Windows Basic Data is added before the data partition.
    disk.goto_partition(&mut reader, basic_data_partition)
        .await?;

    // Convert the LBA range of the partition to a bytes range
    let bytes_part_range = Range {
        start: basic_data_partition.lba_range.start * disk.logical_block_size.get() as u64,
        end: (basic_data_partition.lba_range.last + 1) * disk.logical_block_size.get() as u64,
    };

    Ok(bytes_part_range)
}
