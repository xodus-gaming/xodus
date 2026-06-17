mod parsed;
mod raw;

pub use parsed::*;

mod sealed {
    pub trait Sealed {}
}

/// An XVD binary structure that can be decoded from bytes.
///
/// The conversion from bytes isn't implemented as a trait method because the compiler
/// hates generic constants: "generic parameters may not be used in const operations".
///
/// Implementing this trait means that `impl TryFrom<[u8; XvdStruct::RAW_SIZE]>
/// for Self` exists.
pub trait XvdStruct: Sized + sealed::Sealed {
    const RAW_SIZE: usize;
}

macro_rules! impl_xvd_struct {
    ($parsed:ident) => {
        impl sealed::Sealed for $parsed {}
        impl XvdStruct for $parsed {
            const RAW_SIZE: usize = core::mem::size_of::<raw::$parsed>();
        }

        #[allow(clippy::infallible_try_from)]
        impl TryFrom<[u8; <$parsed as XvdStruct>::RAW_SIZE]> for $parsed {
            type Error = <Self as TryFrom<raw::$parsed>>::Error;

            fn try_from(
                value: [u8; <$parsed as XvdStruct>::RAW_SIZE],
            ) -> Result<Self, Self::Error> {
                let raw: raw::$parsed = zerocopy::transmute!(value);
                Self::try_from(raw)
            }
        }
    };
}

impl_xvd_struct!(XvdHeader);
impl_xvd_struct!(XvdExtEntry);
impl_xvd_struct!(XvdHashEntry);
impl_xvd_struct!(XvcInfo);
impl_xvd_struct!(XvdUpdateSegment);
impl_xvd_struct!(XvcRegionSpecifier);
impl_xvd_struct!(XvcRegionHeader);
impl_xvd_struct!(XvcRegionPresenceInfo);
impl_xvd_struct!(XvdUserDataHeader);
impl_xvd_struct!(XvdUserDataPackageFilesHeader);
impl_xvd_struct!(XvdUserDataPackageFileEntry);
impl_xvd_struct!(XvdSegmentMetadataHeader);
impl_xvd_struct!(XvdSegmentMetadataSegment);
