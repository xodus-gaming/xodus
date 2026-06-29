#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub build: u16,
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

/// An XVD binary structure that can be decoded from bytes.
///
/// The conversion from bytes isn't implemented as a trait method because the compiler
/// hates generic constants: "generic parameters may not be used in const operations".
///
/// Implementing this trait means that `impl TryFrom<[u8; XvdStruct::RAW_SIZE]>
/// for Self` exists.
pub trait XvcStruct: Sized {
    const RAW_SIZE: usize;
}

// This is a macro because the compiler can't handle const generics
macro_rules! read_struct {
    ($t:ty, $reader:expr) => {{
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; <$t as XvcStruct>::RAW_SIZE];
        $reader.read_exact(&mut buf).await?;
        TryInto::<$t>::try_into(buf)
    }};
}

macro_rules! impl_struct {
    ($parsed:ident) => {
        impl XvcStruct for $parsed {
            const RAW_SIZE: usize = core::mem::size_of::<raw::$parsed>();
        }

        #[allow(clippy::infallible_try_from)]
        impl TryFrom<[u8; <$parsed as XvcStruct>::RAW_SIZE]> for $parsed {
            type Error = <Self as TryFrom<raw::$parsed>>::Error;

            fn try_from(
                value: [u8; <$parsed as XvcStruct>::RAW_SIZE],
            ) -> Result<Self, Self::Error> {
                let raw: raw::$parsed = zerocopy::transmute!(value);
                Self::try_from(raw)
            }
        }
    };
}

pub(crate) use impl_struct;
pub(crate) use read_struct;

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
