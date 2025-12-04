use anyhow::Result;

use super::extension::{SignatureAlgorithms, SignatureScheme};

#[derive(Clone, Debug)]
pub enum CertificateRequestExtensionContent {
    SignatureAlgorithms(SignatureAlgorithms),
}

#[derive(Clone, Debug)]
pub struct CertificateRequestExtension {
    pub content: CertificateRequestExtensionContent,
}

impl CertificateRequestExtension {
    pub fn new_signature_algorithms(signature_algorithms: &[SignatureScheme]) -> Self {
        Self {
            content: CertificateRequestExtensionContent::SignatureAlgorithms(SignatureAlgorithms {
                supported_signature_algorithms: Box::from(signature_algorithms),
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CertificateRequest {
    // 8bit
    pub certificate_request_context: Box<[u8]>,
    // 16bit
    pub extensions: Box<[CertificateRequestExtension]>,
}

impl CertificateRequest {
    pub fn new(extensions: &[CertificateRequestExtension]) -> Self {
        Self {
            certificate_request_context: Box::new([]),
            extensions: Box::from(extensions),
        }
    }

    pub fn parse(raw: &[u8]) -> Result<Self> {
        todo!()
    }

    pub fn to_raw(&self) -> Box<[u8]> {
        todo!()
    }
}
