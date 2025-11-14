use anyhow::{Result, anyhow};

// u8
pub enum Command {
    TCP,
    UDP,
}

impl TryFrom<u8> for Command {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::TCP),
            0x02 => Ok(Self::UDP),
            _ => Err(anyhow!("Unknown `Command` value: 0x{value:02X}")),
        }
    }
}

// u8
pub enum AddrType {
    Ipv4,
    Domain,
    Ipv6,
}

impl TryFrom<u8> for AddrType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Ipv4),
            0x02 => Ok(Self::Domain),
            0x03 => Ok(Self::Ipv6),
            _ => Err(anyhow!("Unknown `AddrType` value: 0x{value:02X}")),
        }
    }
}
pub struct VlessRequestHeader {
    pub version: u8,
    pub uuid: u128,
    add_info_length: u8,
    pub add_info: (),
    pub command: Command,
    pub port: u16,
    pub addr_type: AddrType,
    pub addr: (),
}

impl VlessRequestHeader {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let add_info_length = raw[16];
        let offset = add_info_length as usize;

        Ok(Self {
            version: raw[0],
            uuid: u128::from_be_bytes(raw[1..16].try_into()?),
            add_info_length,
            add_info: (),
            command: Command::try_from(raw[17 + offset])?,
            port: u16::from_be_bytes(raw[(18 + offset)..(20 + offset)].try_into()?),
            addr_type: AddrType::try_from(raw[20 + offset])?,
            addr: (),
        })
    }
}
