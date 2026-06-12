// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::ops::RangeInclusive;

use binrw::BinRead;
use crate::error::{NtfsError, Result};
use crate::types::Lcn;

// Sources:
// - https://en.wikipedia.org/wiki/NTFS#Partition_Boot_Sector_(VBR)
// - https://en.wikipedia.org/wiki/BIOS_parameter_block#NTFS
// - https://wiki.osdev.org/NTFS
// - The iBored tool from https://apps.tempel.org/iBored/
#[allow(unused)]
#[derive(BinRead)]
pub(crate) struct BiosParameterBlock {
    sector_size: u16,
    sectors_per_cluster: u8,
    zeros_1: [u8; 7],
    media: u8,
    zeros_2: [u8; 2],
    dummy_sectors_per_track: u16,
    dummy_heads: u16,
    hidden_sectors: u32,
    zeros_3: u32,
    physical_drive_number: u8,
    flags: u8,
    extended_boot_signature: u8,
    reserved: u8,
    total_sectors: u64,
    mft_lcn: Lcn,
    mft_mirror_lcn: Lcn,
    file_record_size_info: i8,
    zeros_4: [u8; 3],
    index_record_size_info: i8,
    zeros_5: [u8; 3],
    serial_number: u64,
    checksum: u32,
}

impl BiosParameterBlock {
    /// Returns the size of a single cluster, in bytes.
    pub(crate) fn cluster_size(&self) -> Result<u32> {
        /// The cluster size cannot go lower than a single sector.
        const MIN_CLUSTER_SIZE: u32 = 512;

        /// The maximum cluster size supported by Windows is 2 MiB.
        /// Source: https://en.wikipedia.org/wiki/NTFS
        const MAX_CLUSTER_SIZE: u32 = 2097152;

        const CLUSTER_SIZE_RANGE: RangeInclusive<u32> = MIN_CLUSTER_SIZE..=MAX_CLUSTER_SIZE;

        // `sectors_per_cluster` and `sector_size` both check for powers of two.
        // Don't need to do that a third time here.
        let cluster_size = self.sectors_per_cluster()? as u32 * self.sector_size()? as u32;
        if !CLUSTER_SIZE_RANGE.contains(&cluster_size) {
            return Err(NtfsError::UnsupportedClusterSize {
                min: MIN_CLUSTER_SIZE,
                max: MAX_CLUSTER_SIZE,
                actual: cluster_size,
            });
        }

        Ok(cluster_size)
    }

    pub(crate) fn file_record_size(&self) -> Result<u32> {
        self.record_size(self.file_record_size_info)
    }

    /// Returns the Logical Cluster Number (LCN) to the beginning of the Master File Table (MFT).
    pub(crate) fn mft_lcn(&self) -> Result<Lcn> {
        if self.mft_lcn.value() > 0 {
            Ok(self.mft_lcn)
        } else {
            Err(NtfsError::InvalidMftLcn)
        }
    }

    /// Source: https://en.wikipedia.org/wiki/NTFS#Partition_Boot_Sector_(VBR)
    fn record_size(&self, size_info: i8) -> Result<u32> {
        // The usual exponent of `BiosParameterBlock::file_record_size_info` is 10 (2^10 = 1024 bytes).
        // For index records, it's usually 12 (2^12 = 4096 bytes).

        /// Exponents < 10 have never been seen and are denied to guarantee that every record header
        /// fits into a record.
        const MIN_EXPONENT: u32 = 10;

        /// Exponents > 12 have neither been seen and are denied to prevent allocating too large buffers.
        const MAX_EXPONENT: u32 = 12;

        const EXPONENT_RANGE: RangeInclusive<u32> = MIN_EXPONENT..=MAX_EXPONENT;

        let cluster_size = self.cluster_size()?;

        if size_info > 0 {
            // The size field denotes a cluster count.
            cluster_size
                .checked_mul(size_info as u32)
                .ok_or(NtfsError::InvalidRecordSizeInfo {
                    size_info,
                    cluster_size,
                })
        } else {
            // The size field denotes a binary exponent after negation.
            let exponent = u32::from(size_info.unsigned_abs());

            if !EXPONENT_RANGE.contains(&exponent) {
                return Err(NtfsError::InvalidRecordSizeInfo {
                    size_info,
                    cluster_size,
                });
            }

            Ok(1 << exponent)
        }
    }

    pub(crate) fn sector_size(&self) -> Result<u16> {
        /// This is the minimum supported by Windows.
        /// NTFS-3G also supports 256-byte sectors, but I haven't seen them anywhere.
        const MIN_SECTOR_SIZE: u16 = 512;

        /// This is the maximum currently supported by Windows.
        /// Tested with Arsenal Image Mounter (https://github.com/ColinFinck/ntfs/issues/14).
        const MAX_SECTOR_SIZE: u16 = 4096;

        const SECTOR_SIZE_RANGE: RangeInclusive<u16> = MIN_SECTOR_SIZE..=MAX_SECTOR_SIZE;

        if !SECTOR_SIZE_RANGE.contains(&self.sector_size) || !self.sector_size.is_power_of_two() {
            return Err(NtfsError::UnsupportedSectorSize {
                min: MIN_SECTOR_SIZE,
                max: MAX_SECTOR_SIZE,
                actual: self.sector_size,
            });
        }

        Ok(self.sector_size)
    }

    fn sectors_per_cluster(&self) -> Result<u16> {
        /// We can't go lower than a single sector per cluster.
        const MIN_SECTORS_PER_CLUSTER: u8 = 1;

        /// 2^12 = 4096 bytes. With 512 bytes sector size, this translates to 2 MiB cluster size,
        /// which is the maximum currently supported by Windows.
        const MAX_EXPONENT: i8 = 12;

        // Cluster sizes from 512 to 64K are represented by taking `self.sectors_per_cluster`
        // as-is (with possible values 1, 2, 4, 8, 16, 32, 64, 128).
        // For larger cluster sizes, `self.sectors_per_cluster` is treated as a binary exponent
        // after negation.
        //
        // See https://dfir.ru/2019/04/23/ntfs-large-clusters/
        if self.sectors_per_cluster > 128 {
            let exponent = -(self.sectors_per_cluster as i8);

            if exponent > MAX_EXPONENT {
                return Err(NtfsError::InvalidSectorsPerCluster {
                    sectors_per_cluster: self.sectors_per_cluster,
                });
            }

            Ok(1 << (exponent as u16))
        } else {
            if self.sectors_per_cluster < MIN_SECTORS_PER_CLUSTER
                || !self.sectors_per_cluster.is_power_of_two()
            {
                return Err(NtfsError::InvalidSectorsPerCluster {
                    sectors_per_cluster: self.sectors_per_cluster,
                });
            }

            Ok(self.sectors_per_cluster as u16)
        }
    }

    pub(crate) fn serial_number(&self) -> u64 {
        self.serial_number
    }

    pub(crate) fn total_sectors(&self) -> u64 {
        self.total_sectors
    }
}

#[allow(unused)]
#[derive(BinRead)]
pub(crate) struct BootSector {
    bootjmp: [u8; 3],
    oem_name: [u8; 8],
    bpb: BiosParameterBlock,
    boot_code: [u8; 426],
    signature: [u8; 2],
}

impl BootSector {
    pub(crate) fn bpb(&self) -> &BiosParameterBlock {
        &self.bpb
    }

    pub(crate) fn validate(&self) -> Result<()> {
        // Some XVD-backed NTFS volumes expose a valid BPB but omit the legacy 0x55AA
        // marker in the first 512-byte VBR record. Accept those volumes here.
        Ok(())
    }
}
