use anyhow::Result;

use crate::handshake::extension::{ExtParent, supported_groups::NamedGroup};

#[derive(Debug)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    // u16 length
    pub key_exchange: Box<[u8]>,
}

#[derive(Debug)]
pub enum KeyShareContent {
    Client(
        // u16 length
        Box<[KeyShareEntry]>,
    ),
    Server(KeyShareEntry),
    Retry(NamedGroup),
}

#[derive(Debug)]
pub struct KeyShare {
    length: u16,

    content: KeyShareContent,
}

impl KeyShare {
    pub fn from_raw(raw: &[u8], source: ExtParent) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);

        let content = match source {
            ExtParent::Server => KeyShareContent::Server(todo!()),
            ExtParent::Client => KeyShareContent::Client(todo!()),
            ExtParent::Retry => KeyShareContent::Retry(todo!()),
        };

        Ok(Self { length, content })
    }
}
