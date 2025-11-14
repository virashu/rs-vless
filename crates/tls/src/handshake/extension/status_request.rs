use anyhow::{Result, bail};

use std::sync::Arc;

#[derive(Debug)]
pub struct StatusRequest {
    length: u16,

    pub responder_id: Arc<[u8]>,
    pub extensions: Arc<[u8]>,
}

impl StatusRequest {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);

        let status_type = raw[2];
        if status_type != 1 {
            bail!("Status type is not 1");
        }

        let mut offset = 3;

        let responder_id_length = u16::from_be_bytes([raw[offset], raw[offset + 1]]) as usize;
        offset += 2;
        let responder_id = raw[offset..(offset + responder_id_length)].into();

        let extensions_length = u16::from_be_bytes([raw[offset], raw[offset + 1]]) as usize;
        offset += 2;
        let extensions = raw[offset..(offset + extensions_length)].into();

        Ok(Self {
            length,
            responder_id,
            extensions,
        })
    }

    pub fn size(&self) -> usize {
        self.length as usize + 2
    }
}
