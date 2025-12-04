use anyhow::Result;

use super::signature_scheme::SignatureScheme;
use crate::parse::{DataVec16, RawDeser};

#[derive(Clone, Debug)]
pub struct SignatureAlgorithms {
    pub supported_signature_algorithms: Box<[SignatureScheme]>,
}

impl SignatureAlgorithms {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let supported_signature_algorithms = DataVec16::<SignatureScheme>::deser(raw)?.into_inner();

        Ok(Self {
            supported_signature_algorithms,
        })
    }
}
