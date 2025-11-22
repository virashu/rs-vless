pub mod client_hello;
pub mod extension;
pub mod server_hello;

use client_hello::ClientHello;
use server_hello::ServerHello;

use anyhow::Result;

use crate::parse::Parse;

pub mod handshake_types {
    pub const SERVER_HELLO: u8 = 2;
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
            1 => Self::ClientHello(ClientHello::parse(data)?),
            handshake_types::SERVER_HELLO => todo!(),
            4 => Self::NewSessionTicket,
            5 => Self::EndOfEarlyData,
            8 => Self::EncryptedExtensions,
            11 => Self::Certificate,
            13 => Self::CertificateRequest,
            15 => Self::CertificateVerify,
            20 => Self::Finished,
            24 => Self::KeyUpdate,
            254 => Self::MessageHash,

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
