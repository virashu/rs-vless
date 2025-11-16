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
    fn parse(raw: &[u8]) -> anyhow::Result<Self> {
        Self::try_from(raw[0])
    }

    fn size(&self) -> usize {
        1
    }
}

#[derive(Debug)]
pub struct PskKeyExchangeModes {
    length: u16,

    pub ke_modes: Box<[PskKeyExchangeMode]>,
}

impl Parse for PskKeyExchangeModes {
    fn parse(raw: &[u8]) -> anyhow::Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);

        let ke_modes = DataVec8::<PskKeyExchangeMode>::parse(&raw[2..])?.into_inner();

        Ok(Self { length, ke_modes })
    }

    fn size(&self) -> usize {
        self.length as usize + 2
    }
}
