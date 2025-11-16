use anyhow::Result;

use crate::{
    handshake::extension::signature_scheme::SignatureScheme,
    parse::{DataVec16, Parse},
};

#[derive(Debug)]
pub struct SignatureAlgorithms {
    pub supported_signature_algorithms: Box<[SignatureScheme]>,
}

impl SignatureAlgorithms {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let supported_signature_algorithms =
            DataVec16::<SignatureScheme>::parse(&raw[2..])?.into_inner();

        Ok(Self {
            supported_signature_algorithms,
        })
    }
}
