use anyhow::Result;

use crate::macros::auto_try_from;

auto_try_from! {
    #[repr(u8)]
    #[derive(Debug)]
    pub enum AlertLevel {
        Warning = 1,
        Fatal = 2,
    }
}

auto_try_from! {
    #[repr(u8)]
    #[derive(Debug)]
    pub enum AlertDescription {
        CloseNotify = 0,
        UnexpectedMessage = 10,
        BadRecordMac = 20,
        RecordOverflow = 22,
        HandshakeFailure = 40,
        BadCertificate = 42,
        UnsupportedCertificate = 43,
        CertificateRevoked = 44,
        CertificateExpired = 45,
        CertificateUnknown = 46,
        IllegalParameter = 47,
        UnknownCa = 48,
        AccessDenied = 49,
        DecodeError = 50,
        DecryptError = 51,
        ProtocolVersion = 70,
        InsufficientSecurity = 71,
        InternalError = 80,
        InappropriateFallback = 86,
        UserCanceled = 90,
        MissingExtension = 109,
        UnsupportedExtension = 110,
        UnrecognizedName = 112,
        BadCertificateStatusResponse = 113,
        UnknownPskIdentity = 115,
        CertificateRequired = 116,
        GeneralError = 117,
        NoApplicationProtocol = 120,
    }
}

#[derive(Debug)]
pub struct Alert {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl Alert {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let level = AlertLevel::try_from(raw[0])?;
        let description = AlertDescription::try_from(raw[1])?;

        Ok(Self { level, description })
    }
}
