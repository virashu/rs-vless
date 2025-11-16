use anyhow::Ok;

use crate::{parse::Parse, util::opaque_vec_8};

#[derive(Debug)]
pub struct RenegotiationInfo {
    length: u16,

    pub renegotiated_connection: Box<[u8]>,
}

impl Parse for RenegotiationInfo {
    fn parse(raw: &[u8]) -> anyhow::Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);

        let (_, renegotiated_connection) = opaque_vec_8(&raw[2..]);

        Ok(Self {
            length,
            renegotiated_connection,
        })
    }

    fn size(&self) -> usize {
        self.length as usize + 2
    }
}
