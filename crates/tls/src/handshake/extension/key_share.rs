use anyhow::Result;

use crate::{
    handshake::extension::named_group::NamedGroup,
    parse::{DataVec16, Parse},
};

#[derive(Debug)]
pub struct KeyShareEntry {
    pub group: NamedGroup,

    size: usize,
    pub key_exchange: Box<[u8]>,
}

impl Parse for KeyShareEntry {
    fn parse(raw: &[u8]) -> Result<Self> {
        let group = NamedGroup::parse(&raw[0..2])?;
        let key_exchange = DataVec16::<u8>::parse(&raw[2..])?;

        Ok(Self {
            group,
            size: key_exchange.size(),
            key_exchange: key_exchange.into_inner(),
        })
    }

    fn size(&self) -> usize {
        self.size + 2
    }
}

#[derive(Debug)]
pub struct KeyShareClientHello {
    length: u16,

    pub client_shares: Box<[KeyShareEntry]>,
}

impl Parse for KeyShareClientHello {
    fn parse(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);
        let client_shares = DataVec16::<KeyShareEntry>::parse(&raw[2..])?.into_inner();

        Ok(Self {
            length,
            client_shares,
        })
    }

    fn size(&self) -> usize {
        self.length as usize + 2
    }
}
