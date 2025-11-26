use tls::record::handshake::extension::{
    ClientHelloExtension, ClientHelloExtensionContent, KeyShareClientHello,
    PreSharedKeyExtensionClientHello, PskKeyExchangeModes, ServerNameList, SignatureAlgorithms,
    StatusRequest, SupportedGroups,
};

pub struct OrganizedClientExtensions {
    pub server_name: Option<ServerNameList>,
    pub status_request: Option<StatusRequest>,
    pub supported_groups: Option<SupportedGroups>,
    pub key_share: Option<KeyShareClientHello>,
    pub signature_algorithms: Option<SignatureAlgorithms>,
    pub psk_key_exchange_modes: Option<PskKeyExchangeModes>,
    pub pre_shared_key: Option<PreSharedKeyExtensionClientHello>,
}

impl OrganizedClientExtensions {
    pub fn organize(exts: Box<[ClientHelloExtension]>) -> Self {
        let mut server_name = None;
        let mut status_request = None;
        let mut supported_groups = None;
        let mut key_share = None;
        let mut signature_algorithms = None;
        let mut psk_key_exchange_modes = None;
        let mut pre_shared_key = None;

        for ext in exts {
            match ext.content {
                ClientHelloExtensionContent::ServerName(e) => {
                    server_name = Some(e);
                }
                ClientHelloExtensionContent::StatusRequest(e) => {
                    status_request = Some(e);
                }
                ClientHelloExtensionContent::SupportedGroups(e) => {
                    supported_groups = Some(e);
                }
                ClientHelloExtensionContent::KeyShare(e) => {
                    key_share = Some(e);
                }
                ClientHelloExtensionContent::SignatureAlgorithms(e) => {
                    signature_algorithms = Some(e);
                }
                ClientHelloExtensionContent::PskKeyExchangeModes(e) => {
                    psk_key_exchange_modes = Some(e);
                }
                ClientHelloExtensionContent::PreSharedKey(e) => {
                    pre_shared_key = Some(e);
                }
                // ClientHelloExtensionContent::EcPointFormats(e) => todo!(),
                // ClientHelloExtensionContent::ApplicationLayerProtocolNegotiation(e) => todo!(),
                // ClientHelloExtensionContent::SignedCertificateTimestamp => todo!(),
                // ClientHelloExtensionContent::ExtendedMainSecret => todo!(),
                // ClientHelloExtensionContent::SessionTicket() => todo!(),
                // ClientHelloExtensionContent::SupportedVersions(e) => {
                //     todo!()
                // }
                // ClientHelloExtensionContent::PostHandshakeAuth => todo!(),
                // ClientHelloExtensionContent::RenegotiationInfo(e) => todo!(),
                _ => {}
            }
        }

        Self {
            server_name,
            status_request,
            supported_groups,
            key_share,
            signature_algorithms,
            psk_key_exchange_modes,
            pre_shared_key,
        }
    }
}
