pub mod alert;
pub mod application_data;
pub mod change_cipher_spec;
pub mod handshake;

use alert::Alert;
use handshake::Handshake;

use anyhow::Result;

use crate::{
    LEGACY_VERSION_BYTES,
    macros::flat,
    parse::{RawDeser, RawSer},
};

pub mod content_types {
    pub const INVALID: u8 = 0;
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    pub const ALERT: u8 = 21;
    pub const HANDSHAKE: u8 = 22;
    pub const APPLICATION_DATA: u8 = 23;
}

#[derive(Clone, Debug)]
pub enum TlsContent {
    Invalid,
    ChangeCipherSpec,
    Alert(Alert),
    Handshake(Handshake),
    ApplicationData,
}

impl TlsContent {
    pub fn content_type(&self) -> u8 {
        match self {
            TlsContent::Invalid => content_types::INVALID,
            TlsContent::ChangeCipherSpec => content_types::CHANGE_CIPHER_SPEC,
            TlsContent::Alert(_) => content_types::ALERT,
            TlsContent::Handshake(_) => content_types::HANDSHAKE,
            TlsContent::ApplicationData => content_types::APPLICATION_DATA,
        }
    }
}

impl RawSer for TlsContent {
    fn ser(&self) -> Box<[u8]> {
        match self {
            TlsContent::Invalid => todo!(),
            TlsContent::ChangeCipherSpec => todo!(),
            TlsContent::Alert(alert) => todo!(),
            TlsContent::Handshake(handshake) => handshake.to_raw(),
            TlsContent::ApplicationData => todo!(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TlsPlaintext {
    length: u16,
    pub fragment: TlsContent,
}

impl RawSer for TlsPlaintext {
    fn ser(&self) -> Box<[u8]> {
        let mut res = Vec::<u8>::new();

        res.push(self.fragment.content_type());
        res.extend(LEGACY_VERSION_BYTES);
        res.extend(self.length.to_be_bytes());
        res.extend(self.fragment.ser());

        res.into_boxed_slice()
    }
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

        Ok(Self {
            length,
            fragment: record,
        })
    }

    pub fn new_handshake(handshake: Handshake) -> Result<Self> {
        Ok(Self {
            length: handshake.to_raw().len().try_into()?,
            fragment: TlsContent::Handshake(handshake),
        })
    }

    pub fn to_raw(&self) -> Box<[u8]> {
        self.ser()
    }
}

pub struct TlsCiphertext {
    // ContentType opaque_type = application_data; /* 23 */
    // ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
    length: u16,
    encrypted_record: Box<[u8]>,
}

impl TlsCiphertext {
    pub fn encrypt(plain: &TlsPlaintext) -> Result<Self> {
        let content = plain.fragment.ser();
        let content_type = plain.fragment.content_type();
        let padding: Vec<u8> = vec![];
        let plaintext = flat!(content, [content_type], &padding);

        #[allow(clippy::cast_possible_truncation)]
        let length = plain.length + padding.len() as u16 + 1;
        let additional_data = flat!([23], LEGACY_VERSION_BYTES, length.to_be_bytes());

        let write_key = todo!();
        let nonce = todo!();

        let AEADEncrypted =
            crypt::aead_aes_256_gcm::encrypt(write_key, nonce, &plaintext, &additional_data);

        todo!()
    }
}

impl RawDeser for TlsCiphertext {
    fn deser(raw: &[u8]) -> Result<Self> {
        // let opaque_type = raw[0];
        // let legacy_record_version = u16::from_be_bytes([raw[1], raw[2]]);

        let length = u16::from_be_bytes([raw[3], raw[4]]);
        let encrypted_record = Box::from(&raw[5..(5 + length as usize)]);

        Ok(Self {
            length,
            encrypted_record,
        })
    }
}
