use crate::models::xsp::raw;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XspHeader {}

#[derive(thiserror::Error, Debug)]
pub enum XspHeaderParseError {
    #[error(r#"invalid magic: expected "MS-XPFM": {0:?}"#)]
    InvalidMagic([u8; 8]),
}

impl XspHeader {
    const MAGIC: [u8; 8] = *b"MS-XPFM ";
}

impl TryFrom<raw::XspHeader> for XspHeader {
    type Error = XspHeaderParseError;

    fn try_from(value: raw::XspHeader) -> Result<Self, Self::Error> {
        if value.magic != Self::MAGIC {
            return Err(XspHeaderParseError::InvalidMagic(value.magic))
        }

        println!("{value:#?}");

        Ok(Self { })
    }
}