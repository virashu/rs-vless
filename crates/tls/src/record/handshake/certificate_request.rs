use anyhow::Result;

use super::extension::CertificateRequestExtension;

#[derive(Debug)]
pub struct CertificateRequest {
    // 8bit
    pub certificate_request_context: Box<[u8]>,
    // 16bit
    pub extensions: Box<[CertificateRequestExtension]>,
}

impl CertificateRequest {
    pub fn new() -> Self {
        todo!()
    }

    pub fn parse(raw: &[u8]) -> Result<Self> {
        todo!()
    }
}
