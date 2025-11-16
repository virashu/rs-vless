use anyhow::Result;

use crate::parse::{DataVec16, Parse};

#[derive(Clone, Debug)]
pub enum ServerName {
    HostName(Box<[u8]>),
}

impl Parse for ServerName {
    fn parse(raw: &[u8]) -> Result<Self> {
        let name_type = raw[0];

        Ok(match name_type {
            0 => {
                let data = DataVec16::<u8>::parse(&raw[1..])?.into_inner();
                Self::HostName(data)
            }
            _ => todo!(),
        })
    }

    fn size(&self) -> usize {
        match self {
            ServerName::HostName(n) => n.len() + 2,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerNameList {
    pub server_name_list: Box<[ServerName]>,
}

impl ServerNameList {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let server_name_list = DataVec16::<ServerName>::parse(raw)?.into_inner();

        Ok(Self { server_name_list })
    }
}
