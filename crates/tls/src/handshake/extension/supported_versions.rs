use anyhow::Result;

use crate::parse::{DataVec8, Parse};

#[derive(Debug)]
pub struct SupportedVersionsClientHello {
    pub versions: Box<[u16]>,
}

impl SupportedVersionsClientHello {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let versions = DataVec8::<u16>::parse(&raw[2..])?.into_inner();

        Ok(Self { versions })
    }
}

#[derive(Clone, Debug)]
pub struct SupportedVersionsServerHello {
    pub selected_version: u16,
}

impl SupportedVersionsServerHello {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let selected_version = u16::from_be_bytes([raw[2], raw[3]]);

        Ok(Self { selected_version })
    }
}
