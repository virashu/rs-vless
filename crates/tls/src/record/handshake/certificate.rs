use crate::parse::{DataVec8, DataVec16, DataVec24};

#[derive(Clone, Debug)]
pub struct CertificateExtension {}

#[derive(Clone, Debug)]
pub enum CertificateEntryContent {
    /// ID: 0
    X509 { cert_data: DataVec24<u8> },
    /// ID: 2
    RawPublicKey {
        asn1_subject_public_key_info: DataVec24<u8>,
    },
}

#[derive(Clone, Debug)]
pub struct CertificateEntry {
    pub content: CertificateEntryContent,

    pub extensions: DataVec16<CertificateExtension>,
}

#[derive(Clone, Debug)]
pub struct Certificate {
    pub certificate_request_context: DataVec8<u8>,
    pub certificate_list: DataVec24<CertificateEntry>,
}
