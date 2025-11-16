use anyhow::Result;

use crate::{
    macros::auto_try_from,
    parse::{DataVec8, Parse},
};

auto_try_from! {
    #[repr(u8)]
    #[allow(non_camel_case_types)]
    #[derive(Debug)]
    pub enum PskKeyExchangeMode {
        psk_ke = 0,
        psk_dhe_ke = 1,
    }
}

impl Parse for PskKeyExchangeMode {
    fn parse(raw: &[u8]) -> Result<Self> {
        Self::try_from(raw[0])
    }

    fn size(&self) -> usize {
        1
    }
}

#[derive(Debug)]
pub struct PskKeyExchangeModes {
    pub ke_modes: Box<[PskKeyExchangeMode]>,
}

impl PskKeyExchangeModes {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let ke_modes = DataVec8::<PskKeyExchangeMode>::parse(raw)?.into_inner();

        Ok(Self { ke_modes })
    }
}
