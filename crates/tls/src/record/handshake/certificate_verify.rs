use crate::{
    parse::{DataVec16, RawDeser, RawSer},
    record::handshake::extension::SignatureScheme,
};

#[derive(Clone, Debug)]
pub struct CertificateVerify {
    pub algorithm: SignatureScheme,
    pub signature: DataVec16<u8>,
}

impl RawSer for CertificateVerify {
    fn ser(&self) -> Box<[u8]> {
        todo!()
    }
}

impl RawDeser for CertificateVerify {
    fn deser(raw: &[u8]) -> anyhow::Result<Self> {
        todo!()
    }
}
