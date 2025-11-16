mod ec_point_formats;
mod key_share;
mod named_group;
mod protocol_name_list;
mod psk_key_exchange_modes;
mod renegotiation_info;
mod server_name;
mod signature_algorithms;
mod signature_scheme;
mod status_request;
mod supported_groups;
mod supported_versions;

pub use ec_point_formats::EcPointFormats;
pub use key_share::KeyShareClientHello;
pub use protocol_name_list::ProtocolNameList;
pub use psk_key_exchange_modes::PskKeyExchangeModes;
pub use renegotiation_info::RenegotiationInfo;
pub use server_name::ServerName;
pub use signature_algorithms::SignatureAlgorithms;
pub use status_request::StatusRequest;
pub use supported_groups::SupportedGroups;
pub use supported_versions::SupportedVersions;

use anyhow::{Context, Result, bail};

use crate::parse::Parse;

#[derive(Debug)]
pub enum ExtensionClientHelloContent {
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
    PskKeyExchangeModes(PskKeyExchangeModes),
    /// ID: 49
    PostHandshakeAuth(/* TODO */),
    /// ID: 51
    KeyShare(KeyShareClientHello),
    /// ID: 65281
    RenegotiationInfo(RenegotiationInfo),
}

impl ExtensionClientHelloContent {
    pub fn size_raw(raw: &[u8]) -> usize {
        u16::from_be_bytes([raw[2], raw[3]]) as usize + 4
    }
}

impl Parse for ExtensionClientHelloContent {
    fn parse(raw: &[u8]) -> Result<Self> {
        let extension_type = u16::from_be_bytes([raw[0], raw[1]]);
        let data = &raw[2..];

        Ok(match extension_type {
            0 => Self::ServerName(ServerName::parse(data).context("ServerName")?),
            5 => Self::StatusRequest(StatusRequest::parse(data).context("StatusRequest")?),
            10 => Self::SupportedGroups(SupportedGroups::parse(data).context("SupportedGroups")?),
            11 => Self::EcPointFormats(EcPointFormats::parse(data).context("EcPointFormats")?),
            13 => Self::SignatureAlgorithms(
                SignatureAlgorithms::parse(data).context("SignatureAlgorigthms")?,
            ),
            16 => Self::ApplicationLayerProtocolNegotiation(
                ProtocolNameList::parse(data).context("ALPNegotiation")?,
            ),
            23 => Self::ExtendedMainSecret,
            35 => Self::SessionTicket(),
            43 => Self::SupportedVersions(SupportedVersions::parse(data)?),
            45 => Self::PskKeyExchangeModes(PskKeyExchangeModes::parse(data)?),
            // 49 => Self::PostHandshakeAuth(),
            51 => Self::KeyShare(KeyShareClientHello::parse(data)?),
            65281 => Self::RenegotiationInfo(RenegotiationInfo::parse(data)?),

            _ => bail!("Unknown extension type: {extension_type}"),
        })
    }

    #[allow(clippy::match_same_arms)]
    fn size(&self) -> usize {
        2 + match self {
            Self::ServerName(e) => e.size(),
            Self::StatusRequest(e) => e.size(),
            Self::SupportedGroups(e) => e.size(),
            Self::SignatureAlgorithms(e) => e.size(),
            Self::SupportedVersions(e) => e.size(),
            Self::EcPointFormats(e) => e.size(),
            Self::ApplicationLayerProtocolNegotiation(e) => e.size(),
            Self::KeyShare(e) => e.size(),
            Self::RenegotiationInfo(e) => e.size(),
            Self::PskKeyExchangeModes(e) => e.size(),

            // Empty indicator
            Self::ExtendedMainSecret => 2,

            Self::SessionTicket() => 2,

            Self::PostHandshakeAuth() => todo!(),
        }
    }
}

// #[derive(Debug)]
// pub struct ExtensionClientHello {
//     length: u16,

//     pub content: ExtensionClientHelloContent,
// }
