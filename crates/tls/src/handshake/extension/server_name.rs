use anyhow::Result;

#[derive(Debug)]
pub struct ServerName {
    length: u16,
}

impl ServerName {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);

        Ok(Self { length })
    }

    pub fn size(&self) -> usize {
        self.length as usize
    }
}
