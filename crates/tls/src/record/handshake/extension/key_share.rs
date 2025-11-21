use anyhow::Result;

use super::named_group::NamedGroup;
use crate::parse::{DataVec16, Parse};

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct KeyShareClientHello {
    pub client_shares: Box<[KeyShareEntry]>,
}

impl KeyShareClientHello {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let client_shares = DataVec16::<KeyShareEntry>::parse(raw)?.into_inner();

        Ok(Self { client_shares })
    }
}
