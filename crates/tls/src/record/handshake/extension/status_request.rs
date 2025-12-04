use anyhow::{Result, bail};

use crate::util::opaque_vec_16;

#[derive(Clone, Debug)]
pub struct StatusRequest {
    pub responder_id: Box<[u8]>,
    pub extensions: Box<[u8]>,
}

impl StatusRequest {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let status_type = raw[0];
        if status_type != 1 {
            bail!("Status type is not 1");
        }

        let mut offset = 1;

        let (size, responder_id) = opaque_vec_16(&raw[offset..]);
        offset += size;

        let (_, extensions) = opaque_vec_16(&raw[offset..]);

        Ok(Self {
            responder_id,
            extensions,
        })
    }
}
