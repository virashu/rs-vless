use anyhow::{Ok, Result};

use crate::{macros::auto_try_from, util::opaque_vec_8};

auto_try_from! {
    #[repr(u8)]
    #[derive(Debug)]
    pub enum EcPointFormat {
        Uncompressed = 0,
        Deprecated1 = 1,
        Deprecated2 = 2,
    }
}

#[derive(Debug)]
pub struct EcPointFormats {
    length: u16,

    pub ec_point_format_list: Box<[EcPointFormat]>,
}

impl EcPointFormats {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);

        let (_, data) = opaque_vec_8(&raw[2..]);
        let ec_point_format_list = data
            .into_iter()
            .filter_map(|el| EcPointFormat::try_from(el).ok())
            .collect();

        Ok(Self {
            length,
            ec_point_format_list,
        })
    }

    pub fn size(&self) -> usize {
        self.length as usize + 2
    }
}
