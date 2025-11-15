use anyhow::Result;

use crate::util::{opaque_vec_8, opaque_vec_16};

#[derive(Debug)]
pub struct ProtocolNameList {
    length: u16,

    pub protocol_name_list: Box<[Box<[u8]>]>,
}

impl ProtocolNameList {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);

        let (_, data) = opaque_vec_16(&raw[2..]);
        let total_length = data.len();
        let mut parsed_length = 0;
        let mut protocol_name_list = Vec::new();
        while parsed_length < total_length {
            let (size, data) = opaque_vec_8(&data[parsed_length..]);
            parsed_length += size;

            protocol_name_list.push(data);
        }

        Ok(Self {
            length,
            protocol_name_list: protocol_name_list.into_boxed_slice(),
        })
    }

    pub fn size(&self) -> usize {
        self.length as usize + 2
    }
}
