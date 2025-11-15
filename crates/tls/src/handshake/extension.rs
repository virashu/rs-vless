mod server_name;
mod signature_algorithms;
mod status_request;
mod supported_groups;
mod supported_versions;

pub use server_name::ServerName;
pub use signature_algorithms::SignatureAlgorithms;
pub use status_request::StatusRequest;
pub use supported_groups::SupportedGroups;
pub use supported_versions::SupportedVersions;

use anyhow::{Result, bail};

#[derive(Debug)]
pub enum Extension {
    /// ID: 0
    ServerName(ServerName),
    /// ID: 5
    StatusRequest(StatusRequest),
    /// ID: 10
    SupportedGroups(SupportedGroups),
    /// ID: 11
    EcPointFormats(/* TODO */),
    /// ID: 13
    SignatureAlgorithms(SignatureAlgorithms),
    /// ID: 16
    ApplicationLayerProtocolNegotiation(/* TODO */),
    /// ID: 23
    ExtendedMainSecret(/* TODO */),
    /// ID: 35
    SessionTicket(/* TODO */),
    /// ID: 43
    SupportedVersions(SupportedVersions),
    /// ID: 45
    PskKeyExchangeModes(/* TODO */),
    /// ID: 49
    PostHandshakeAuth(/* TODO */),
    /// ID: 51
    KeyShare(/* TODO */),
    /// ID: 65281
    RenegotiationInfo(/* TODO */),
}

impl Extension {
    pub fn size_raw(raw: &[u8]) -> usize {
        u16::from_be_bytes([raw[2], raw[3]]) as usize + 4
    }

    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let extension_type = u16::from_be_bytes([raw[0], raw[1]]);
        let data = &raw[2..];

        Ok(match extension_type {
            0 => Self::ServerName(ServerName::from_raw(data)?),
            5 => Self::StatusRequest(StatusRequest::from_raw(data)?),
            10 => Self::SupportedGroups(SupportedGroups::from_raw(data)?),
            13 => Self::SignatureAlgorithms(SignatureAlgorithms::from_raw(data)?),
            35 => Self::SessionTicket(),
            43 => Self::SupportedVersions(SupportedVersions::from_raw(data)?),

            _ => bail!("Unknown extension type: {extension_type}"),
        })
    }

    pub fn size(&self) -> usize {
        2 + match self {
            Self::ServerName(e) => e.size(),
            Self::StatusRequest(e) => e.size(),
            Self::SupportedGroups(e) => e.size(),
            Self::SignatureAlgorithms(e) => e.size(),
            Self::SessionTicket() => 2,
            Self::SupportedVersions(e) => e.size(),

            Self::EcPointFormats() => todo!(),
            Self::ApplicationLayerProtocolNegotiation() => todo!(),
            Self::ExtendedMainSecret() => todo!(),
            Self::PskKeyExchangeModes() => todo!(),
            Self::PostHandshakeAuth() => todo!(),
            Self::KeyShare() => todo!(),
            Self::RenegotiationInfo() => todo!(),
        }
    }
}
