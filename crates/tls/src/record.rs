use anyhow::Result;

use crate::{LEGACY_VERSION_BYTES, alert::Alert, handshake::Handshake};

pub mod content_types {
    pub const INVALID: u8 = 0;
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    pub const ALERT: u8 = 21;
    pub const HANDSHAKE: u8 = 22;
    pub const APPLICATION_DATA: u8 = 23;
}

#[derive(Debug)]
pub enum TlsContent {
    Invalid,
    ChangeCipherSpec,
    Alert(Alert),
    Handshake(Handshake),
    ApplicationData,
}

#[derive(Debug)]
pub struct TlsPlaintext {
    length: u16,
    pub record: TlsContent,
}

impl TlsPlaintext {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let content_type = raw[0];
        let length = u16::from_be_bytes([raw[3], raw[4]]);

        let data = &raw[5..];

        let record = match content_type {
            content_types::INVALID => TlsContent::Invalid,
            content_types::CHANGE_CIPHER_SPEC => TlsContent::ChangeCipherSpec,
            content_types::ALERT => TlsContent::Alert(Alert::from_raw(data)?),
            content_types::HANDSHAKE => TlsContent::Handshake(Handshake::from_raw(data)?),
            content_types::APPLICATION_DATA => TlsContent::ApplicationData,

            _ => todo!(),
        };

        Ok(Self { length, record })
    }

    pub fn new_handshake(handshake: Handshake) -> Result<Self> {
        Ok(Self {
            length: handshake.to_raw().len().try_into()?,
            record: TlsContent::Handshake(handshake),
        })
    }

    pub fn to_raw(&self) -> Box<[u8]> {
        match &self.record {
            TlsContent::Handshake(hs) => {
                let mut res = Vec::<u8>::new();

                res.push(content_types::HANDSHAKE);
                res.extend(LEGACY_VERSION_BYTES);
                res.extend(self.length.to_be_bytes());
                res.extend(&hs.to_raw());

                res.into_boxed_slice()
            }

            _ => todo!(),
        }
    }
}
