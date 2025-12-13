use anyhow::Result;

use crate::{
    parse::{DataVec16, RawDeser, RawSize},
    util::opaque_vec_8,
};

#[derive(Clone, Debug)]
pub struct ProtocolName {
    size: usize,

    pub data: Box<[u8]>,
}

impl RawSize for ProtocolName {
    fn size(&self) -> usize {
        self.size
    }
}

impl RawDeser for ProtocolName {
    fn deser(raw: &[u8]) -> Result<Self> {
        let (size, data) = opaque_vec_8(raw);
        Ok(Self { size, data })
    }
}

#[derive(Clone, Debug)]
pub struct ProtocolNameList {
    pub protocol_name_list: Box<[ProtocolName]>,
}

impl RawDeser for ProtocolNameList {
    fn deser(raw: &[u8]) -> Result<Self> {
        let protocol_name_list = DataVec16::<ProtocolName>::deser(raw)?.into_inner();

        Ok(Self { protocol_name_list })
    }
}
