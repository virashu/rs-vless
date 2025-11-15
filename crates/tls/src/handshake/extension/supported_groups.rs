use anyhow::Result;

use crate::{
    handshake::extension::named_group::NamedGroup,
    parse::{DataVec16, Parse},
};

#[derive(Debug)]
pub struct SupportedGroups {
    length: u16,

    pub named_group_list: Box<[NamedGroup]>,
}

impl Parse for SupportedGroups {
    fn parse(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);
        let named_group_list = DataVec16::<NamedGroup>::parse(&raw[2..])?.into_inner();

        Ok(Self {
            length,
            named_group_list,
        })
    }

    fn size(&self) -> usize {
        self.length as usize + 2
    }
}
