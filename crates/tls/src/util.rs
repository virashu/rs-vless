#[allow(clippy::range_plus_one)]
pub fn opaque_vec_8(raw: &[u8]) -> (usize, Box<[u8]>) {
    let length = raw[0] as usize;
    let data = raw[1..(1 + length)].into();
    (1 + length, data)
}

pub fn opaque_vec_16(raw: &[u8]) -> (usize, Box<[u8]>) {
    let length = u16::from_be_bytes([raw[0], raw[1]]) as usize;
    let data = raw[2..(2 + length)].into();
    (2 + length, data)
}
