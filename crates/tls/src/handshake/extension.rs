mod ec_point_formats;
mod key_share;
mod named_group;
mod pre_shared_key;
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
pub use server_name::ServerNameList;
pub use signature_algorithms::SignatureAlgorithms;
pub use status_request::StatusRequest;
pub use supported_groups::SupportedGroups;
pub use supported_versions::{SupportedVersionsClientHello, SupportedVersionsServerHello};

use anyhow::{Context, Result, bail};

use crate::{
    handshake::extension::pre_shared_key::{
        PreSharedKeyExtensionClientHello, PreSharedKeyExtensionServerHello,
    },
    parse::Parse,
};

#[derive(Debug)]
pub enum ClientHelloExtensionContent {
    /// ID: 0
    ServerName(ServerNameList),
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
    /// ID: 41
    PreSharedKey(PreSharedKeyExtensionClientHello),
    /// ID: 43
    SupportedVersions(SupportedVersionsClientHello),
    /// ID: 45
    PskKeyExchangeModes(PskKeyExchangeModes),
    /// ID: 49
    PostHandshakeAuth,
    /// ID: 51
    KeyShare(KeyShareClientHello),
    /// ID: 65281
    RenegotiationInfo(RenegotiationInfo),
}

impl ClientHelloExtensionContent {
    fn parse(raw: &[u8]) -> Result<Self> {
        let extension_type = u16::from_be_bytes([raw[0], raw[1]]);
        let data = &raw[4..];

        Ok(match extension_type {
            0 => Self::ServerName(ServerNameList::parse(data).context("ServerName")?),
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
            41 => Self::PreSharedKey(PreSharedKeyExtensionClientHello::parse(data)?),
            43 => Self::SupportedVersions(SupportedVersionsClientHello::parse(data)?),
            45 => Self::PskKeyExchangeModes(PskKeyExchangeModes::parse(data)?),
            49 => Self::PostHandshakeAuth,
            51 => Self::KeyShare(KeyShareClientHello::parse(data)?),
            65281 => Self::RenegotiationInfo(RenegotiationInfo::parse(data)?),

            _ => bail!("Unknown extension type: {extension_type}"),
        })
    }
}

#[derive(Debug)]
pub struct ClientHelloExtension {
    length: u16,

    pub content: ClientHelloExtensionContent,
}

impl ClientHelloExtension {
    pub fn size_raw(raw: &[u8]) -> usize {
        u16::from_be_bytes([raw[2], raw[3]]) as usize + 4
    }
}

impl Parse for ClientHelloExtension {
    fn parse(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[2], raw[3]]);
        let content = ClientHelloExtensionContent::parse(raw)?;

        Ok(Self { length, content })
    }

    fn size(&self) -> usize {
        self.length as usize + 4
    }
}

#[derive(Clone, Debug)]
pub enum ServerHelloExtensionContent {
    /// ID: 41
    PreSharedKey(PreSharedKeyExtensionServerHello),
    /// ID: 43
    SupportedVersions(SupportedVersionsServerHello),
    /// ID: 51
    KeyShare(KeyShareClientHello),
}

#[derive(Clone, Debug)]
pub struct ServerHelloExtension {
    length: u16,

    pub content: ServerHelloExtensionContent,
}

impl ServerHelloExtension {
    pub fn length(&self) -> u16 {
        self.length
    }

    pub fn size(&self) -> usize {
        todo!()
    }

    pub fn to_raw(&self) -> Box<[u8]> {
        todo!()
    }
}
