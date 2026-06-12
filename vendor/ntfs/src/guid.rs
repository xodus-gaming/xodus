// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use binrw::BinRead;

/// Size of a single GUID on disk (= size of all GUID fields).
pub(crate) const GUID_SIZE: usize = 16;

/// A Globally Unique Identifier (GUID), used for Object IDs in NTFS.
#[derive(BinRead, Clone, Debug, Eq, PartialEq)]
pub struct NtfsGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl fmt::Display for NtfsGuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:8X}-{:4X}-{:4X}-{:2X}{:2X}-{:2X}{:2X}{:2X}{:2X}{:2X}{:2X}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guid() {
        let guid = NtfsGuid {
            data1: 0x67c8770b,
            data2: 0x44f1,
            data3: 0x410a,
            data4: [0xab, 0x9a, 0xf9, 0xb5, 0x44, 0x6f, 0x13, 0xee],
        };
        let guid_string = guid.to_string();
        assert_eq!(guid_string, "67C8770B-44F1-410A-AB9A-F9B5446F13EE");
    }
}
