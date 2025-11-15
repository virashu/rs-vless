pub mod client_hello;
pub mod extension;
pub mod server_hello;

use anyhow::Result;

use crate::handshake::{client_hello::ClientHello, server_hello::ServerHello};

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
        let length = u32::from_be_bytes([0, raw[1], raw[2], raw[3]]);

        Ok(match msg_type {
            1 => Self::ClientHello(ClientHello::from_raw(&raw[1..])?),
            2 => Self::ServerHello(todo!()),
            4 => Self::NewSessionTicket,
            5 => Self::EndOfEarlyData,
            8 => Self::EncryptedExtensions,
            11 => Self::Certificate,
            13 => Self::CertificateRequest,
            15 => Self::CertificateVerify,
            20 => Self::Finished,
            24 => Self::KeyUpdate,
            254 => Self::MessageHash,

            _ => todo!(),
        })
    }

    pub fn to_raw(&self) -> Box<[u8]> {
        match self {
            Handshake::ServerHello(server_hello) => server_hello.to_raw(),
            _ => todo!(),
        }
    }
}
