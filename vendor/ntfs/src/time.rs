// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use binrw::BinRead;
use derive_more::From;

#[cfg(feature = "time")]
use {crate::error::NtfsError, time::OffsetDateTime};

#[cfg(feature = "std")]
use std::time::{SystemTime, SystemTimeError};

/// Difference in 100-nanosecond intervals between the Windows/NTFS epoch (1601-01-01) and the Unix epoch (1970-01-01).
#[cfg(any(feature = "time", feature = "std"))]
const EPOCH_DIFFERENCE_IN_INTERVALS: u64 = 116_444_736_000_000_000;

/// Number of 100-nanosecond intervals in a second.
#[cfg(any(feature = "time", feature = "std"))]
const INTERVALS_PER_SECOND: u64 = 10_000_000;

/// An NTFS timestamp, used for expressing file times.
///
/// NTFS (and the Windows NT line of operating systems) represent time as an unsigned 64-bit integer
/// counting the number of 100-nanosecond intervals since January 1, 1601.
#[derive(BinRead, Clone, Copy, Debug, Eq, From, Ord, PartialEq, PartialOrd)]
pub struct NtfsTime(u64);

impl NtfsTime {
    /// Returns the stored NT timestamp (number of 100-nanosecond intervals since January 1, 1601).
    pub fn nt_timestamp(&self) -> u64 {
        self.0
    }
}

#[cfg(feature = "time")]
#[cfg_attr(docsrs, doc(cfg(feature = "time")))]
impl TryFrom<OffsetDateTime> for NtfsTime {
    type Error = NtfsError;

    fn try_from(dt: OffsetDateTime) -> Result<Self, Self::Error> {
        let nanos_since_unix_epoch = dt.unix_timestamp_nanos();
        let intervals_since_unix_epoch = nanos_since_unix_epoch / 100;
        let intervals_since_windows_epoch =
            intervals_since_unix_epoch + EPOCH_DIFFERENCE_IN_INTERVALS as i128;
        let nt_timestamp =
            u64::try_from(intervals_since_windows_epoch).map_err(|_| NtfsError::InvalidTime)?;

        Ok(Self(nt_timestamp))
    }
}

#[cfg(feature = "time")]
#[cfg_attr(docsrs, doc(cfg(feature = "time")))]
impl From<NtfsTime> for OffsetDateTime {
    fn from(nt: NtfsTime) -> OffsetDateTime {
        let intervals_since_windows_epoch = nt.nt_timestamp() as i128;
        let intervals_since_unix_epoch =
            intervals_since_windows_epoch - EPOCH_DIFFERENCE_IN_INTERVALS as i128;
        let nanos_since_unix_epoch = intervals_since_unix_epoch * 100;

        OffsetDateTime::from_unix_timestamp_nanos(nanos_since_unix_epoch).unwrap()
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl TryFrom<SystemTime> for NtfsTime {
    type Error = SystemTimeError;

    fn try_from(st: SystemTime) -> Result<Self, Self::Error> {
        let duration_since_unix_epoch = st.duration_since(SystemTime::UNIX_EPOCH)?;
        let intervals_since_unix_epoch = duration_since_unix_epoch.as_secs() * INTERVALS_PER_SECOND
            + duration_since_unix_epoch.subsec_nanos() as u64 / 100;
        let intervals_since_windows_epoch =
            intervals_since_unix_epoch + EPOCH_DIFFERENCE_IN_INTERVALS;

        Ok(Self(intervals_since_windows_epoch))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[cfg(feature = "time")]
    use time::macros::datetime;

    pub(crate) const NT_TIMESTAMP_2021_01_01: u64 = 132539328000000000u64;

    #[cfg(feature = "time")]
    #[test]
    fn test_offsetdatetime() {
        let dt = datetime!(2013-01-05 18:15 UTC);
        let nt = NtfsTime::try_from(dt).unwrap();
        assert_eq!(nt.nt_timestamp(), 130018833000000000u64);

        let dt2 = OffsetDateTime::from(nt);
        assert_eq!(dt, dt2);

        let dt = datetime!(1601-01-01 0:00 UTC);
        let nt = NtfsTime::try_from(dt).unwrap();
        assert_eq!(nt.nt_timestamp(), 0u64);

        let dt = datetime!(1600-12-31 23:59:59 UTC);
        assert!(NtfsTime::try_from(dt).is_err());

        let dt = datetime!(+60056-05-28 0:00 UTC);
        assert!(NtfsTime::try_from(dt).is_ok());

        let dt = datetime!(+60056-05-29 0:00 UTC);
        assert!(NtfsTime::try_from(dt).is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_systemtime() {
        let st = SystemTime::now();
        let nt = NtfsTime::try_from(st).unwrap();
        assert!(nt.nt_timestamp() > NT_TIMESTAMP_2021_01_01);
    }
}
