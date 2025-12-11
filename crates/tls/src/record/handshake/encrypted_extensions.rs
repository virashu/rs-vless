use anyhow::Result;

use crate::parse::{DataVec16, RawDeser, RawSer, RawSize};

#[derive(Clone, Debug)]
pub struct EncryptedExtensionsExtension {}

impl RawSer for EncryptedExtensionsExtension {
    fn ser(&self) -> Box<[u8]> {
        todo!()
    }
}

impl RawDeser for EncryptedExtensionsExtension {
    fn deser(raw: &[u8]) -> Result<Self> {
        todo!()
    }
}

impl RawSize for EncryptedExtensionsExtension {
    fn size(&self) -> usize {
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
}

impl RawSer for EncryptedExtensions {
    fn ser(&self) -> Box<[u8]> {
        self.extensions.ser()
    }
}

impl RawDeser for EncryptedExtensions {
    fn deser(raw: &[u8]) -> Result<Self> {
        Ok(Self {
            extensions: DataVec16::deser(raw)?,
        })
    }
}
