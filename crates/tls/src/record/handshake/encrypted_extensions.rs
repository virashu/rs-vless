use anyhow::Result;

use crate::parse::{DataVec16, RawSer};

#[derive(Clone, Debug)]
pub struct EncryptedExtensionsExtension {}

impl RawSer for EncryptedExtensionsExtension {
    fn ser(&self) -> Box<[u8]> {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct EncryptedExtensions {
    extensions: DataVec16<EncryptedExtensionsExtension>,
}

impl EncryptedExtensions {
    pub fn new() -> Self {
        Self {
            extensions: DataVec16::new(),
        }
    }

    pub fn parse(raw: &[u8]) -> Result<Self> {
        todo!()
    }
}

impl RawSer for EncryptedExtensions {
    fn ser(&self) -> Box<[u8]> {
        self.extensions.ser()
    }
}
