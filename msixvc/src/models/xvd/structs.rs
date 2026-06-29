mod parsed;
mod raw;

pub use parsed::*;

use crate::models::common::*;

impl_struct!(XvdHeader);
impl_struct!(XvdExtEntry);
impl_struct!(XvdHashEntry);
impl_struct!(XvcInfo);
impl_struct!(XvdUpdateSegment);
impl_struct!(XvcRegionSpecifier);
impl_struct!(XvcRegionHeader);
impl_struct!(XvcRegionPresenceInfo);
impl_struct!(XvdUserDataHeader);
impl_struct!(XvdUserDataPackageFilesHeader);
impl_struct!(XvdUserDataPackageFileEntry);
impl_struct!(XvdSegmentMetadataHeader);
impl_struct!(XvdSegmentMetadataSegment);
