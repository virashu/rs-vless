use anyhow::Result;

use crate::{
    parse::{DataVec16, Parse},
    util::opaque_vec_8,
};

#[derive(Clone, Debug)]
pub struct ProtocolName {
    size: usize,

    pub data: Box<[u8]>,
}

impl Parse for ProtocolName {
    fn parse(raw: &[u8]) -> Result<Self> {
        let (size, data) = opaque_vec_8(raw);
        Ok(Self { size, data })
    }

    fn size(&self) -> usize {
        self.size
    }
}

#[derive(Clone, Debug)]
pub struct ProtocolNameList {
    pub protocol_name_list: Box<[ProtocolName]>,
}

impl ProtocolNameList {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let protocol_name_list = DataVec16::<ProtocolName>::parse(raw)?.into_inner();

        Ok(Self { protocol_name_list })
    }
}
