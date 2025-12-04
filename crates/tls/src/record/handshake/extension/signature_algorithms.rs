use anyhow::Result;

use super::signature_scheme::SignatureScheme;
use crate::parse::{DataVec16, Parse};

#[derive(Clone, Debug)]
pub struct SignatureAlgorithms {
    pub supported_signature_algorithms: Box<[SignatureScheme]>,
}

impl SignatureAlgorithms {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let supported_signature_algorithms = DataVec16::<SignatureScheme>::parse(raw)?.into_inner();

        Ok(Self {
            supported_signature_algorithms,
        })
    }
}
