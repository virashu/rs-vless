use anyhow::{Ok, Result};

use crate::{
    macros::auto_try_from,
    parse::{DataVec8, Parse},
};

auto_try_from! {
    #[repr(u8)]
    #[derive(Debug)]
    pub enum EcPointFormat {
        Uncompressed = 0,
        Deprecated1 = 1,
        Deprecated2 = 2,
    }
}

impl Parse for EcPointFormat {
    fn parse(raw: &[u8]) -> Result<Self> {
        Self::try_from(raw[0])
    }

    fn size(&self) -> usize {
        1
    }
}

#[derive(Debug)]
pub struct EcPointFormats {
    length: u16,

    pub ec_point_format_list: Box<[EcPointFormat]>,
}

impl Parse for EcPointFormats {
    fn parse(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);

        let ec_point_format_list = DataVec8::<EcPointFormat>::parse(&raw[2..])?.into_inner();

        Ok(Self {
            length,
            ec_point_format_list,
        })
    }

    fn size(&self) -> usize {
        self.length as usize + 2
    }
}
