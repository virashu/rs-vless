mod constants;
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

pub use constants::extension_types;
pub use ec_point_formats::EcPointFormats;
pub use key_share::KeyShareClientHello;
pub use pre_shared_key::{PreSharedKeyExtensionClientHello, PreSharedKeyExtensionServerHello};
pub use protocol_name_list::ProtocolNameList;
pub use psk_key_exchange_modes::PskKeyExchangeModes;
pub use renegotiation_info::RenegotiationInfo;
pub use server_name::{ServerName, ServerNameList};
pub use signature_algorithms::SignatureAlgorithms;
pub use status_request::StatusRequest;
pub use supported_groups::SupportedGroups;
pub use supported_versions::{SupportedVersionsClientHello, SupportedVersionsServerHello};

use anyhow::{Context, Result, bail};

use crate::parse::Parse;

#[cfg_attr(feature = "trace", derive(strum_macros::AsRefStr))]
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
    /// ID: 18
    SignedSertificateTimestamp,
    /// ID: 23
    ExtendedMainSecret,
    // 27
    // 28
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
    // 65037
    /// ID: 65281
    RenegotiationInfo(RenegotiationInfo),
}

impl ClientHelloExtensionContent {
    fn parse(raw: &[u8]) -> Result<Self> {
        let extension_type = u16::from_be_bytes([raw[0], raw[1]]);
        let data = &raw[4..];

        Ok(match extension_type {
            extension_types::SERVER_NAME => {
                Self::ServerName(ServerNameList::parse(data).context("ServerName")?)
            }
            extension_types::STATUS_REQUEST => {
                Self::StatusRequest(StatusRequest::parse(data).context("StatusRequest")?)
            }
            extension_types::SUPPORTED_GROUPS => {
                Self::SupportedGroups(SupportedGroups::parse(data).context("SupportedGroups")?)
            }
            extension_types::EC_POINT_FORMATS => {
                Self::EcPointFormats(EcPointFormats::parse(data).context("EcPointFormats")?)
            }
            extension_types::SIGNATURE_ALGORITHMS => Self::SignatureAlgorithms(
                SignatureAlgorithms::parse(data).context("SignatureAlgorigthms")?,
            ),
            extension_types::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                Self::ApplicationLayerProtocolNegotiation(
                    ProtocolNameList::parse(data).context("ALPNegotiation")?,
                )
            }
            18 => Self::SignedSertificateTimestamp,
            extension_types::EXTENDED_MAIN_SECRET => Self::ExtendedMainSecret,
            extension_types::SESSION_TICKET => Self::SessionTicket(),
            extension_types::PRE_SHARED_KEY => {
                Self::PreSharedKey(PreSharedKeyExtensionClientHello::parse(data)?)
            }
            extension_types::SUPPORTED_VERSIONS => {
                Self::SupportedVersions(SupportedVersionsClientHello::parse(data)?)
            }
            extension_types::PSK_KEY_EXCHANGE_MODES => {
                Self::PskKeyExchangeModes(PskKeyExchangeModes::parse(data)?)
            }
            extension_types::POST_HANDSHAKE_AUTH => Self::PostHandshakeAuth,
            extension_types::KEY_SHARE => Self::KeyShare(KeyShareClientHello::parse(data)?),
            extension_types::RENEGOTIATION_INFO => {
                Self::RenegotiationInfo(RenegotiationInfo::parse(data)?)
            }

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
    pub fn new_supported_versions(version: u16) -> Self {
        Self {
            length: 2,
            content: ServerHelloExtensionContent::SupportedVersions(SupportedVersionsServerHello {
                selected_version: version,
            }),
        }
    }

    pub fn length(&self) -> u16 {
        self.length
    }

    pub fn size(&self) -> usize {
        self.length as usize + 2
    }

    pub fn to_raw(&self) -> Box<[u8]> {
        match &self.content {
            ServerHelloExtensionContent::PreSharedKey(_e) => {
                todo!()
            }
            ServerHelloExtensionContent::SupportedVersions(e) => [
                extension_types::SUPPORTED_VERSIONS.to_be_bytes(),
                [0, 2],
                e.selected_version.to_be_bytes(),
            ]
            .concat()
            .into(),
            ServerHelloExtensionContent::KeyShare(_e) => todo!(),
        }
    }
}
