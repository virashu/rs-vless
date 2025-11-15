use anyhow::Result;

use crate::parse::Parse;

#[derive(Debug)]
pub struct ServerName {
    length: u16,
}

impl Parse for ServerName {
    fn parse(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);

        Ok(Self { length })
    }

    fn size(&self) -> usize {
        self.length as usize
    }
}
