//! <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf>

use anyhow::{Result, ensure};

use crate::block_cipher::{
    BlockCipher,
    aes::{Aes, Aes128Cipher, Aes256Cipher},
};

fn xor(mut a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    for i in 0..16 {
        a[i] ^= b[i];
    }
    a
}

fn xor_dyn(a: &[u8], b: &[u8]) -> Result<Box<[u8]>> {
    ensure!(a.len() == b.len(), "Len is not equal");

    Ok(a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect())
}

fn mul(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    const R: u128 = 0xE1 << 120;

    let x = u128::from_be_bytes(x);

    let mut product = 0u128;
    let mut v = u128::from_be_bytes(y);

    for i in 0..128 {
        if (x >> (127 - i)) & 1 == 1 {
            product ^= v;
        }

        let lsb = v & 1 == 1;
        v >>= 1;
        if lsb {
            v ^= R;
        }
    }

    product.to_be_bytes()
}

fn inc<const N: usize>(y: [u8; N]) -> [u8; N] {
    let a0: [u8; 4] = y[(y.len() - 4)..].try_into().unwrap();
    let a1 = u32::from_be_bytes(a0).wrapping_add(1);

    let mut res = Vec::new();
    res.extend(&y[..(y.len() - 4)]);
    res.extend(a1.to_be_bytes());

    res.as_slice().try_into().unwrap()
}

fn ghash(hash_key: &[u8; 16], value: &[u8]) -> Result<[u8; 16]> {
    ensure!(value.len() % 16 == 0);

    let mut hash = [0; 16];

    for block in value.as_chunks().0 {
        let xor_res = xor(hash, *block);
        hash = mul(xor_res, *hash_key);
    }

    Ok(hash)
}

/// Encrypt `input` with `block_cipher`
/// using `initial_counter` as a starting value for counter
fn gctr(
    block_cipher: &dyn BlockCipher,
    initial_counter: [u8; 16],
    input: &[u8],
) -> Result<Box<[u8]>> {
    if input.is_empty() {
        return Ok(Box::new([]));
    }

    let mut counter = initial_counter;
    let (blocks, remainder) = input.as_chunks::<16>();
    let mut ciphertext: Vec<u8> = Vec::new();

    for block_i in blocks {
        let key_i: [u8; 16] = (*block_cipher.encrypt(&counter)).try_into()?;

        let ciphertext_i = xor(*block_i, key_i);
        ciphertext.extend(ciphertext_i);
        counter = inc(counter);
    }

    let key_n: [u8; 16] = (*block_cipher.encrypt(&counter)).try_into()?;
    let block_n = remainder;
    let ciphertext_n = xor_dyn(block_n, &key_n[..(block_n.len())])?;
    ciphertext.extend(ciphertext_n);

    Ok(ciphertext.into_boxed_slice())
}

type Ciphertext = Box<[u8]>;
type Tag = Box<[u8]>;

#[allow(clippy::missing_errors_doc)]
pub fn encrypt(
    block_cipher: &dyn BlockCipher,
    iv: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
) -> Result<(Ciphertext, Tag)> {
    let hash_key: [u8; 16] = (*block_cipher.encrypt(&[0; 16])).try_into()?;

    let counter_initial: [u8; 16] = if iv.len() == 12 {
        let mut x = [0; 16];
        x[0..12].copy_from_slice(iv);
        x[12..16].copy_from_slice(&1u32.to_be_bytes());
        x
    } else {
        let mut x = Vec::new();
        let s = 16 * iv.len().div_ceil(16) - iv.len();
        x.extend(iv);
        x.extend([0].repeat(s + 8));
        x.extend((iv.len() as u64).to_be_bytes());
        ghash(&hash_key, &x)?
    };

    let ciphertext = gctr(block_cipher, inc(counter_initial), plaintext)?;

    let tag_block_input = {
        let u = 16 * ciphertext.len().div_ceil(16) - ciphertext.len();
        let v = 16 * additional_data.len().div_ceil(16) - additional_data.len();

        let mut acc = Vec::new();

        acc.extend(additional_data);
        acc.extend([0u8].repeat(v));

        acc.extend(&ciphertext);
        acc.extend([0u8].repeat(u));

        acc.extend(((additional_data.len() * 8) as u64).to_be_bytes());
        acc.extend(((ciphertext.len() * 8) as u64).to_be_bytes());

        acc
    };
    let tag_block = ghash(&hash_key, &tag_block_input)?;
    let tag = gctr(block_cipher, counter_initial, &tag_block)?;

    Ok((ciphertext, tag))
}

pub fn encrypt_aes_128_gcm(
    secret: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
) -> Result<(Box<[u8]>, Box<[u8]>)> {
    let block_cipher = Aes::new(Aes128Cipher::new(secret.try_into()?));

    encrypt(&block_cipher, iv, plaintext, additional_data)
}

pub fn encrypt_aes_256_gcm(
    secret: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
) -> Result<(Box<[u8]>, Box<[u8]>)> {
    let block_cipher = Aes::new(Aes256Cipher::new(secret.try_into()?));

    encrypt(&block_cipher, iv, plaintext, additional_data)
}

/// <https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf>
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_aes_128_gcm_1() {
        let key = [0; 16];
        let iv = [0; 12];
        let plaintext = [];
        let ad = [];

        let (c, t) = encrypt_aes_128_gcm(&key, &iv, &plaintext, &ad).unwrap();

        assert_eq!(*c, []);
        assert_eq!(
            *t,
            [
                0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
                0x45, 0x5a,
            ]
        );
    }

    #[test]
    fn test_aead_aes_128_gcm_2() {
        let key = [0; 16];
        let iv = [0; 12];
        let plaintext = [0; 16];
        let ad = [];

        let (c, t) = encrypt_aes_128_gcm(&key, &iv, &plaintext, &ad).unwrap();

        assert_eq!(
            *c,
            [
                0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
                0xfe, 0x78,
            ]
        );
        assert_eq!(
            *t,
            [
                0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
                0xbd, 0xdf,
            ]
        );
    }

    /// Test Case 3
    #[test]
    fn test_aead_aes_128_gcm_3() {
        let key = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08,
        ];
        let iv = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let plaintext = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
        ];
        let ad = [];

        let (c, t) = encrypt_aes_128_gcm(&key, &iv, &plaintext, &ad).unwrap();

        assert_eq!(
            *c,
            [
                0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0,
                0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23,
                0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f,
                0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
                0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85,
            ]
        );
        assert_eq!(
            *t,
            [
                0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd, 0x64, 0xa6, 0x2c, 0xf3, 0x5a, 0xbd, 0x2b, 0xa6,
                0xfa, 0xb4,
            ]
        );
    }

    /// Test Case 13
    #[test]
    fn test_aead_aes_256_gcm_1() {
        let key = [0; 32];
        let iv = [0; 12];
        let plaintext = [];
        let ad = [];

        let (c, t) = encrypt_aes_256_gcm(&key, &iv, &plaintext, &ad).unwrap();

        assert_eq!(*c, []);
        assert_eq!(
            *t,
            [
                0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
                0x73, 0x8b
            ]
        );
    }

    /// Test Case 14
    #[test]
    fn test_aead_aes_256_gcm_2() {
        let key = [0; 32];
        let iv = [0; 12];
        let plaintext = [0; 16];
        let ad = [];

        let (c, t) = encrypt_aes_256_gcm(&key, &iv, &plaintext, &ad).unwrap();

        assert_eq!(
            *c,
            [
                0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
                0x9d, 0x18,
            ]
        );
        assert_eq!(
            *t,
            [
                0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a,
                0xb9, 0x19,
            ]
        );
    }
}
