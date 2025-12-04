use anyhow::Result;

use crate::parse::{DataVec8, DataVec16, RawSer, RawSize};

use super::extension::{SignatureAlgorithms, SignatureScheme};

#[derive(Clone, Debug)]
pub enum CertificateRequestExtensionContent {
    SignatureAlgorithms(SignatureAlgorithms),
}

#[derive(Clone, Debug)]
pub struct CertificateRequestExtension {
    pub content: CertificateRequestExtensionContent,
}

impl RawSize for CertificateRequestExtension {
    fn size(&self) -> usize {
        todo!()
    }
}

impl RawSer for CertificateRequestExtension {
    fn ser(&self) -> Box<[u8]> {
        todo!()
    }
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
    pub certificate_request_context: DataVec8<u8>,
    pub extensions: DataVec16<CertificateRequestExtension>,
}

impl CertificateRequest {
    pub fn new(extensions: &[CertificateRequestExtension]) -> Result<Self> {
        Ok(Self {
            certificate_request_context: DataVec8::new(),
            extensions: DataVec16::try_from(extensions)?,
        })
    }

    pub fn parse(raw: &[u8]) -> Result<Self> {
        todo!()
    }

    pub fn to_raw(&self) -> Box<[u8]> {
        let mut res = Vec::new();

        res.extend(self.certificate_request_context.ser());
        res.extend(self.extensions.ser());

        res.into_boxed_slice()
    }
}
