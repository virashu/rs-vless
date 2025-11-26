pub mod client_hello;
pub mod extension;
pub mod server_hello;

use client_hello::ClientHello;
use server_hello::ServerHello;

use anyhow::Result;

use crate::parse::Parse;

pub mod handshake_types {
    pub const CLIENT_HELLO: u8 = 1;
    pub const SERVER_HELLO: u8 = 2;
    pub const NEW_SESSION_TICKET: u8 = 4;
    pub const END_OF_EARLY_DATA: u8 = 5;
    pub const ENCRYPTED_EXTENSIONS: u8 = 8;
    pub const CERTIFICATE: u8 = 11;
    pub const CERTIFICATE_REQUEST: u8 = 13;
    pub const CERTIFICATE_VERIFY: u8 = 15;
    pub const FINISHED: u8 = 20;
    pub const KEY_UPDATE: u8 = 24;
    pub const MESSAGE_HASH: u8 = 254;
}

#[derive(Debug)]
pub enum Handshake {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    EndOfEarlyData,
    EncryptedExtensions,
    CertificateRequest,
    Certificate,
    CertificateVerify,
    Finished,
    NewSessionTicket,
    KeyUpdate,

    MessageHash,
}

impl Handshake {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let msg_type = raw[0];
        let data = &raw[1..];
        let _length = u32::from_be_bytes([0, raw[1], raw[2], raw[3]]);

        Ok(match msg_type {
            handshake_types::CLIENT_HELLO => Self::ClientHello(ClientHello::parse(data)?),
            handshake_types::SERVER_HELLO => todo!(),
            handshake_types::NEW_SESSION_TICKET => Self::NewSessionTicket,
            handshake_types::END_OF_EARLY_DATA => Self::EndOfEarlyData,
            handshake_types::ENCRYPTED_EXTENSIONS => Self::EncryptedExtensions,
            handshake_types::CERTIFICATE => Self::Certificate,
            handshake_types::CERTIFICATE_REQUEST => Self::CertificateRequest,
            handshake_types::CERTIFICATE_VERIFY => Self::CertificateVerify,
            handshake_types::FINISHED => Self::Finished,
            handshake_types::KEY_UPDATE => Self::KeyUpdate,
            handshake_types::MESSAGE_HASH => Self::MessageHash,

            _ => todo!("{msg_type}"),
        })
    }

    pub fn to_raw(&self) -> Box<[u8]> {
        match self {
            Handshake::ServerHello(s_h) => {
                let mut res = Vec::new();

                res.push(handshake_types::SERVER_HELLO);

                let raw = s_h.to_raw();
                let length = raw.len();
                tracing::info!(?length);
                let length_bytes = TryInto::<u32>::try_into(length)
                    .expect("Server hello size exceeds maximum u32 value")
                    .to_be_bytes();

                tracing::info!(?length_bytes);
                res.extend(&length_bytes[1..=3]);

                res.extend(raw);

                res.into_boxed_slice()
            }
            _ => todo!(),
        }
    }
}
