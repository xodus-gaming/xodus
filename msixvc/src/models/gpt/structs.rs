mod parsed;
mod raw;

pub use parsed::*;

use crate::models::common::impl_struct;

impl_struct!(GptHeader);
impl_struct!(PartitionEntry);
