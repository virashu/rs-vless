use anyhow::Ok;

use crate::util::opaque_vec_8;

#[derive(Debug)]
pub struct RenegotiationInfo {
    pub renegotiated_connection: Box<[u8]>,
}

impl RenegotiationInfo {
    pub fn parse(raw: &[u8]) -> anyhow::Result<Self> {
        let (_, renegotiated_connection) = opaque_vec_8(raw);

        Ok(Self {
            renegotiated_connection,
        })
    }
}
