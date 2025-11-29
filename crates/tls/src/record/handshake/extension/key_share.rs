use std::collections::HashMap;

use anyhow::Result;

use super::named_group::NamedGroup;
use crate::parse::{DataVec16, Parse};

#[derive(Clone, Debug)]
pub struct KeyShareEntry {
    pub group: NamedGroup,

    size: usize,
    pub key_exchange: Box<[u8]>,
}

impl KeyShareEntry {
    pub fn new(group: NamedGroup, key: &[u8]) -> Self {
        Self {
            group,
            size: key.len() + 2,
            key_exchange: Box::from(key),
        }
    }

    pub fn to_raw(&self) -> Box<[u8]> {
        let mut res = Vec::new();

        let group: u16 = (&self.group).into();
        res.extend(group.to_be_bytes());

        let length = self.key_exchange.len() as u16;
        res.extend(length.to_be_bytes());

        res.extend(&self.key_exchange);

        res.into_boxed_slice()
    }
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

    pub fn to_hashmap(&self) -> HashMap<NamedGroup, Box<[u8]>> {
        self.client_shares
            .iter()
            .cloned()
            .map(|share| (share.group, share.key_exchange))
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct KeyShareServerHello {
    pub server_share: KeyShareEntry,
}
