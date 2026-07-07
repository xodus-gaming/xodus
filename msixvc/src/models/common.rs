#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub build: u16,
}

impl Version {
    /// Creates a [`Version`] from a field array.
    ///
    /// The input is expected as it appears in the XVD header, where the least significant
    /// version component comes first: `[build, patch, minor, major]`.
    pub fn from_fields(value: [u16; 4]) -> Self {
        Self {
            major: value[3],
            minor: value[2],
            patch: value[1],
            build: value[0],
        }
    }
}

impl std::cmp::Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then(self.build.cmp(&other.build))
    }
}

impl std::cmp::PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.patch, self.build
        )
    }
}

impl std::fmt::Debug for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Use the Display implementation as the Debug one
        write!(f, "{}", self)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ReadError<E> {
    #[error(transparent)]
    Io(#[from] tokio::io::Error),

    #[error(transparent)]
    Parse(E),
}

macro_rules! impl_struct {
    ($parsed:ident) => {
        impl $parsed {
            pub const RAW_SIZE: usize = core::mem::size_of::<raw::$parsed>();

            pub fn from_array(
                array: [u8; Self::RAW_SIZE],
            ) -> Result<Self, <Self as TryFrom<raw::$parsed>>::Error> {
                let raw: raw::$parsed = zerocopy::transmute!(array);
                Self::try_from(raw)
            }

            /// Panics if the slice length is less than [`Self::RAW_SIZE`].
            pub fn from_slice(
                slice: &[u8],
            ) -> Result<Self, <Self as TryFrom<raw::$parsed>>::Error> {
                assert!(slice.len() >= Self::RAW_SIZE);
                Self::from_array(slice[..Self::RAW_SIZE].try_into().unwrap())
            }

            pub async fn read<R: tokio::io::AsyncRead + Unpin>(
                mut reader: R,
            ) -> Result<
                Self,
                crate::models::common::ReadError<<Self as TryFrom<raw::$parsed>>::Error>,
            > {
                let mut array = [0u8; Self::RAW_SIZE];
                tokio::io::AsyncReadExt::read_exact(&mut reader, &mut array).await?;
                Self::from_array(array).map_err(|e| crate::models::common::ReadError::Parse(e))
            }
        }
    };
}

pub(crate) use impl_struct;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_cmp() {
        let lower = Version {
            major: 1,
            minor: 26,
            patch: 3005,
            build: 0,
        };
        let higher = Version {
            major: 1,
            minor: 26,
            patch: 3101,
            build: 0,
        };
        let other_high = Version {
            major: 1,
            minor: 26,
            patch: 3101,
            build: 0,
        };
        let other_high2 = Version {
            major: 2,
            minor: 26,
            patch: 3101,
            build: 0,
        };

        assert!(lower < higher);
        assert!(higher > lower);
        assert!(higher == other_high);
        assert!(other_high2 > other_high);
    }
}
