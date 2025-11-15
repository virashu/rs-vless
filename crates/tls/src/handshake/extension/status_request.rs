use anyhow::{Result, bail};

use crate::{parse::Parse, util::opaque_vec_16};

#[derive(Debug)]
pub struct StatusRequest {
    length: u16,

    pub responder_id: Box<[u8]>,
    pub extensions: Box<[u8]>,
}

impl Parse for StatusRequest {
    fn parse(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);

        let status_type = raw[2];
        if status_type != 1 {
            bail!("Status type is not 1");
        }

        let mut offset = 3;

        let (size, responder_id) = opaque_vec_16(&raw[offset..]);
        offset += size;

        let (_, extensions) = opaque_vec_16(&raw[offset..]);

        Ok(Self {
            length,
            responder_id,
            extensions,
        })
    }

    fn size(&self) -> usize {
        self.length as usize + 2
    }
}
