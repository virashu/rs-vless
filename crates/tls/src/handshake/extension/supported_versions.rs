use anyhow::Result;

use crate::parse::{DataVec8, Parse};

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

impl Parse for SupportedVersions {
    fn parse(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);

        let content = if length == 2 {
            SupportedVersionsContent::Server(u16::from_be_bytes([raw[2], raw[3]]))
        } else {
            let data = DataVec8::<u16>::parse(&raw[2..])?.into_inner();
            SupportedVersionsContent::Client(data)
        };

        Ok(Self { length, content })
    }

    fn size(&self) -> usize {
        self.length as usize + 2
    }
}
