use anyhow::Result;

use crate::{
    handshake::extension::signature_scheme::SignatureScheme,
    parse::{DataVec16, Parse},
};

#[derive(Debug)]
pub struct SignatureAlgorithms {
    length: u16,

    pub supported_signature_algorithms: Box<[SignatureScheme]>,
}

impl Parse for SignatureAlgorithms {
    fn parse(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);

        let supported_signature_algorithms =
            DataVec16::<SignatureScheme>::parse(&raw[2..])?.into_inner();

        Ok(Self {
            length,
            supported_signature_algorithms,
        })
    }

    fn size(&self) -> usize {
        self.length as usize + 2
    }
}
