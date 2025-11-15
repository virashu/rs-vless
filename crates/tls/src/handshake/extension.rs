mod ec_point_formats;
mod key_share;
mod protocol_name_list;
mod server_name;
mod signature_algorithms;
mod status_request;
mod supported_groups;
mod supported_versions;

pub use protocol_name_list::ProtocolNameList;
pub use server_name::ServerName;
pub use signature_algorithms::SignatureAlgorithms;
pub use status_request::StatusRequest;
pub use supported_groups::SupportedGroups;
pub use supported_versions::SupportedVersions;

use anyhow::{Result, bail};

use crate::handshake::extension::{ec_point_formats::EcPointFormats, key_share::KeyShare};

#[derive(Clone, Copy, Debug)]
pub enum ExtParent {
    Server,
    Client,
    Retry,
}

#[derive(Debug)]
pub enum Extension {
    /// ID: 0
    ServerName(ServerName),
    /// ID: 5
    StatusRequest(StatusRequest),
    /// ID: 10
    SupportedGroups(SupportedGroups),
    /// ID: 11
    EcPointFormats(EcPointFormats),
    /// ID: 13
    SignatureAlgorithms(SignatureAlgorithms),
    /// ID: 16
    ApplicationLayerProtocolNegotiation(ProtocolNameList),
    /// ID: 23
    ExtendedMainSecret,
    /// ID: 35
    SessionTicket(/* TODO */),
    /// ID: 43
    SupportedVersions(SupportedVersions),
    /// ID: 45
    PskKeyExchangeModes(/* TODO */),
    /// ID: 49
    PostHandshakeAuth(/* TODO */),
    /// ID: 51
    KeyShare(KeyShare),
    /// ID: 65281
    RenegotiationInfo(/* TODO */),
}

impl Extension {
    pub fn size_raw(raw: &[u8]) -> usize {
        u16::from_be_bytes([raw[2], raw[3]]) as usize + 4
    }

    pub fn from_raw(raw: &[u8], source: ExtParent) -> Result<Self> {
        let extension_type = u16::from_be_bytes([raw[0], raw[1]]);
        let data = &raw[2..];

        Ok(match extension_type {
            0 => Self::ServerName(ServerName::from_raw(data)?),
            5 => Self::StatusRequest(StatusRequest::from_raw(data)?),
            10 => Self::SupportedGroups(SupportedGroups::from_raw(data)?),
            11 => Self::EcPointFormats(EcPointFormats::from_raw(data)?),
            13 => Self::SignatureAlgorithms(SignatureAlgorithms::from_raw(data)?),
            16 => Self::ApplicationLayerProtocolNegotiation(ProtocolNameList::from_raw(data)?),
            23 => Self::ExtendedMainSecret,
            35 => Self::SessionTicket(),
            43 => Self::SupportedVersions(SupportedVersions::from_raw(data)?),
            49 => Self::PostHandshakeAuth(),
            51 => Self::KeyShare(KeyShare::from_raw(data, source)?),

            _ => bail!("Unknown extension type: {extension_type}"),
        })
    }

    #[allow(clippy::match_same_arms)]
    pub fn size(&self) -> usize {
        2 + match self {
            Self::ServerName(e) => e.size(),
            Self::StatusRequest(e) => e.size(),
            Self::SupportedGroups(e) => e.size(),
            Self::SignatureAlgorithms(e) => e.size(),
            Self::SupportedVersions(e) => e.size(),
            Self::EcPointFormats(e) => e.size(),
            Self::ApplicationLayerProtocolNegotiation(e) => e.size(),

            Self::SessionTicket() => 2,
            Self::ExtendedMainSecret => 2,

            Self::KeyShare(e) => todo!(),

            Self::PskKeyExchangeModes() => todo!(),
            Self::PostHandshakeAuth() => todo!(),
            Self::RenegotiationInfo() => todo!(),
        }
    }
}
