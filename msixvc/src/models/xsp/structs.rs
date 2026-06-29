pub mod parsed;
pub mod raw;

use crate::models::common::*;
pub use parsed::*;

impl_struct!(XspHeader);
impl_struct!(XspPatchRecord);
