pub trait Sealed {}

/// An XVD binary structure that can be decoded from bytes.
///
/// The conversion from bytes isn't implemented as a trait method because the compiler
/// hates generic constants: "generic parameters may not be used in const operations".
///
/// Implementing this trait means that `impl TryFrom<[u8; XvdStruct::RAW_SIZE]>
/// for Self` exists.
pub trait XvcStruct: Sized + Sealed {
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
        impl Sealed for $parsed {}
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
