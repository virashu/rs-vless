use anyhow::Result;

pub fn encrypt(
    secret: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
) -> Result<Box<[u8]>> {
    todo!()
}
