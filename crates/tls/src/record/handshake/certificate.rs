#[derive(Clone, Debug)]
pub struct CertificateExtension {}

#[derive(Clone, Debug)]
pub enum CertificateEntryContent {
    /// ID: 0
    X509 {
        // 24bit
        cert_data: Box<[u8]>,
    },
    /// ID: 2
    RawPublicKey {
        // 24bit
        asn1_subject_public_key_info: Box<[u8]>,
    },
}

#[derive(Clone, Debug)]
struct CertificateEntry {
    pub content: CertificateEntryContent,

    // 16bit
    extensions: Box<[CertificateExtension]>,
}

#[derive(Clone, Debug)]
struct Certificate {
    // 8bit
    certificate_request_context: Box<[u8]>,
    // 24bit
    certificate_list: Box<[CertificateEntry]>,
}
