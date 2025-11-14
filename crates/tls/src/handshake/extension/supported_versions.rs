use anyhow::Result;

#[derive(Debug)]
pub enum SupportedVersionsContent {
    Client(Box<[u16]>),
    Server(u16),
}

#[derive(Debug)]
pub struct SupportedVersions {
    length: u16,
    content: SupportedVersionsContent,
}

impl SupportedVersions {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);

        let content = if length == 2 {
            SupportedVersionsContent::Server(u16::from_be_bytes([raw[2], raw[3]]))
        } else {
            let len = raw[2] as usize;
            let v = raw[3..(len + 3)]
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            SupportedVersionsContent::Client(v)
        };

        Ok(Self { length, content })
    }

    pub fn size(&self) -> usize {
        self.length as usize + 2
    }

    pub fn server(&self) -> Option<u16> {
        match self.content {
            SupportedVersionsContent::Server(v) => Some(v),
            SupportedVersionsContent::Client(_) => None,
        }
    }

    pub fn client(&self) -> Option<&[u16]> {
        match self.content {
            SupportedVersionsContent::Client(ref vs) => Some(vs.as_ref()),
            SupportedVersionsContent::Server(_) => None,
        }
    }
}
