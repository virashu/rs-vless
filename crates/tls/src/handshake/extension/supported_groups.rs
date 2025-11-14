use anyhow::Result;

use crate::macros::auto_try_from;

auto_try_from! {
    #[repr(u16)]
    #[allow(non_camel_case_types)]
    #[derive(Debug)]
    pub enum NamedGroup {
        /* Elliptic Curve Groups (ECDHE) */
        secp256r1 = 0x0017,
        secp384r1 = 0x0018,
        secp521r1 = 0x0019,
        x25519 = 0x001D,
        x448 = 0x001E,

        /* Finite Field Groups (DHE) */
        ffdhe2048 = 0x0100,
        ffdhe3072 = 0x0101,
        ffdhe4096 = 0x0102,
        ffdhe6144 = 0x0103,
        ffdhe8192 = 0x0104,
    }
}

#[derive(Debug)]
pub struct SupportedGroups {
    length: u16,

    pub named_group_list: Vec<NamedGroup>,
}

impl SupportedGroups {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);

        let named_group_list_length = u16::from_be_bytes([raw[2], raw[3]]) as usize;
        let named_group_list = raw[4..(named_group_list_length + 4)]
            .chunks_exact(2)
            .filter_map(|c| NamedGroup::try_from(u16::from_be_bytes([c[0], c[1]])).ok())
            .collect();

        Ok(Self {
            length,
            named_group_list,
        })
    }

    pub fn size(&self) -> usize {
        self.length as usize + 2
    }
}
