use anyhow::Result;

use crate::{alert::Alert, handshake::Handshake};

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
            0 => TlsContent::Invalid,
            20 => TlsContent::ChangeCipherSpec,
            21 => TlsContent::Alert(Alert::from_raw(data)?),
            22 => TlsContent::Handshake(Handshake::from_raw(data)?),
            23 => TlsContent::ApplicationData,

            _ => todo!(),
        };

        Ok(Self { length, record })
    }

    pub fn new_handshake(handshake: Handshake) -> Self {
        Self {
            length: handshake.to_raw().len() as u16,
            record: TlsContent::Handshake(handshake),
        }
    }

    pub fn to_raw(&self) -> Box<[u8]> {
        match &self.record {
            TlsContent::Handshake(hs) => {
                let mut res = Vec::<u8>::new();

                res.extend([22, 3, 3]);
                res.extend(self.length.to_be_bytes());
                res.extend(&hs.to_raw());

                res.into_boxed_slice()
            }

            _ => todo!(),
        }
    }
}
