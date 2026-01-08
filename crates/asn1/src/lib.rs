use num_bigint::BigUint;

pub mod native_tags {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OBJECT_IDENTIFIER: u8 = 0x06;
    pub const IA5_STRING: u8 = 0x16; // Primitive

    pub const SEQUENCE: u8 = 0x30; // Constructed
}

#[allow(clippy::cast_possible_truncation, reason = "expected behavior")]
fn encode_object_identifier_component(mut value: u32) -> Box<[u8]> {
    if value <= 0x7F {
        return Box::new([value as u8]);
    }

    let mut res_le = Vec::new();
    res_le.push(value as u8 & 0x7F);
    value >>= 7;

    while value != 0 {
        res_le.push(value as u8 & 0x7F | 0x80);
        value >>= 7;
    }

    res_le.reverse();
    res_le.into_boxed_slice()
}

fn decode_object_identifier_component(raw: &[u8]) -> u32 {
    let mut res = 0u32;

    for byte in raw {
        res <<= 7;
        res += u32::from(byte & 0x7F);
    }

    res
}

fn decode_object_identifier(raw: &[u8]) -> Box<[u32]> {
    let mut subs = raw.chunk_by(|x, _| x & 0x80 != 0);

    let mut res = Vec::new();

    {
        let first = decode_object_identifier_component(subs.next().unwrap());
        res.push(first / 40);
        res.push(first % 40);
    }

    for sub in subs {
        res.push(decode_object_identifier_component(sub));
    }

    res.into_boxed_slice()
}

enum Length {
    Definite(usize),
    Indefinite,
}

impl Length {
    pub fn parse(raw: &mut dyn Iterator<Item = u8>) -> Self {
        let octet_1 = raw.next().unwrap();
        let is_short = (octet_1 >> 7) == 0;
        let data = octet_1 & 0b0111_1111;

        if is_short {
            return Self::Definite(data as usize);
        }

        if data == 0 {
            return Self::Indefinite;
        }

        assert!(data != 0x7f, "Reserved");

        if data > 4 {
            unimplemented!("Length in octets is too big");
        }
        let mut bytes = [0u8; 4];
        bytes[(4 - data as usize)..]
            .copy_from_slice(&raw.take(data as usize).collect::<Box<[u8]>>());
        let len = u32::from_be_bytes(bytes);

        Self::Definite(len as usize)
    }
}

#[derive(Debug)]
pub enum DataElement {
    EndOfContent,
    Boolean(bool),
    Integer(BigUint),
    BitString,
    OctetString(Box<[u8]>),
    Null,
    ObjectIdentifier(Box<[u32]>),
    ObjectDescriptor,
    External,
    Real(f32),
    Enumerated,
    Sequence(Box<[DataElement]>),
    IA5String(Box<str>),
}

impl DataElement {
    pub fn parse(raw: &mut dyn Iterator<Item = u8>) -> Self {
        let tag = raw.next().unwrap();
        // let tag_class = tag >> 6;
        // let is_constructed = (tag >> 5) & 1 != 0;
        // let tag_type = tag & 0b11111;

        let length = Length::parse(raw);
        let Length::Definite(len) = length else {
            unimplemented!()
        };

        match tag {
            native_tags::SEQUENCE => {
                let mut sub = raw.take(len).peekable();
                let mut elements = Vec::new();

                while sub.peek().is_some() {
                    elements.push(Self::parse(&mut sub));
                }

                Self::Sequence(elements.into_boxed_slice())
            }

            native_tags::INTEGER => Self::Integer(BigUint::from_bytes_be(
                &raw.take(len).collect::<Box<[u8]>>(),
            )),

            native_tags::OCTET_STRING => Self::OctetString(raw.take(len).collect()),

            native_tags::NULL => Self::Null,

            native_tags::OBJECT_IDENTIFIER => {
                let bytes = raw.take(len).collect::<Box<[u8]>>();

                Self::ObjectIdentifier(decode_object_identifier(&bytes))
            }

            native_tags::IA5_STRING => {
                let bytes = raw.take(len).collect::<Box<[u8]>>();
                let string = String::from_utf8_lossy(&bytes);

                Self::IA5String(Box::from(string))
            }

            _ => unimplemented!("0x{:02x}", tag),
        }
    }
}

pub fn parse_der(raw: &[u8]) -> DataElement {
    let mut iter = raw.iter().copied();
    DataElement::parse(&mut iter)
}
