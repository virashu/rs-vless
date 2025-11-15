use anyhow::Result;

use crate::{
    parse::{DataVec16, Parse},
    util::opaque_vec_8,
};

#[derive(Debug)]
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

#[derive(Debug)]
pub struct ProtocolNameList {
    length: u16,

    pub protocol_name_list: Box<[ProtocolName]>,
}

impl Parse for ProtocolNameList {
    fn parse(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);

        let protocol_name_list = DataVec16::<ProtocolName>::parse(&raw[2..])?.into_inner();

        Ok(Self {
            length,
            protocol_name_list,
        })
    }

    fn size(&self) -> usize {
        self.length as usize + 2
    }
}
