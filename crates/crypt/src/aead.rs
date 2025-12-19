use anyhow::{Result, ensure};
use num_bigint::BigUint;

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

fn mul_n(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let a = BigUint::from_bytes_be(&a);
    let b = BigUint::from_bytes_be(&b);

    // GF(2^128)
    // = x^128 + x^7 + x^2 + x + 1
    let modulo = (BigUint::from(1u32) << 128) + BigUint::from(0b1000_0111u32);

    // let mut c: BigUint = a * b;
    // if c >= (BigUint::from(1u32) << 128) {
    //     c ^= BigUint::from(0b1000_0111u32);
    // }
    // let part: BigUint = c % (BigUint::from(1u32) << 128);

    let cut: BigUint = (a * b) % modulo;

    let res = cut.to_bytes_be();

    let n = res.len();
    let mut r = [0; 16];
    r[..n].copy_from_slice(&res[..n]);
    r
}

fn mul(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    const R: u128 = 0xe1 << 120;

    let x = u128::from_be_bytes(x);

    let mut product = 0u128;
    let mut v = u128::from_be_bytes(y);

    println!("* MUL | {x:016x} x {v:016x}");

    for i in 0..128 {
        if (x >> i) & 1 == 1 {
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

fn incr_by<const N: usize>(y: [u8; N], i: u32) -> Result<[u8; N]> {
    let a0: [u8; 4] = y[(y.len() - 4)..].try_into()?;
    let a1 = u32::from_be_bytes(a0).overflowing_add(i).0;
    let mut res = Vec::new();
    res.extend(&y[..(y.len() - 4)]);
    res.extend(a1.to_be_bytes());
    let y: [u8; N] = res.as_slice().try_into().unwrap();
    Ok(y)
}

fn g_hash(hash_key: &[u8; 16], a: &[u8], c: &[u8]) -> [u8; 16] {
    let blocks = {
        let mut acc = Vec::new();

        if !a.is_empty() {
            let (a_blocks, a_remainder) = a.as_chunks::<16>();
            acc.extend(a_blocks);
            acc.push({
                let mut pad = [0; 16];
                pad[..a_remainder.len()].copy_from_slice(a_remainder);
                pad
            });
        }

        if !c.is_empty() {
            let (c_blocks, c_remainder) = c.as_chunks::<16>();
            acc.extend(c_blocks);
            acc.push({
                let mut pad = [0; 16];
                pad[..c_remainder.len()].copy_from_slice(c_remainder);
                pad
            });
        }

        acc.push({
            let a_len: [u8; 8] = ((a.len() * 8) as u64).to_be_bytes();
            let c_len: [u8; 8] = ((c.len() * 8) as u64).to_be_bytes();
            [a_len, c_len].concat().try_into().unwrap()
        });

        acc
    };

    let mut x = [0; 16];

    // 0x0388dace60b6a392f328c2b971b2fe78 * 0x66e94bd4ef8a2c3b884cfa59ca342b2e
    // = 0x5e2ec746917062882c85b0685353deb7
    for (block, i) in blocks.into_iter().zip(1..) {
        println!("BLOCK #{i}: {block:02x?}");

        let xor_res = xor(x, block);
        println!("XOR #{i}:   {xor_res:02x?}");

        x = mul_n(xor_res, *hash_key);
        println!("X_{i}\t= {x:02x?}");
        println!();
    }

    x
}

#[allow(clippy::type_complexity)]
#[allow(clippy::missing_errors_doc)]
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::many_single_char_names)]
pub fn encrypt(
    block_cipher: &dyn BlockCipher,
    iv: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
) -> Result<(Box<[u8]>, Box<[u8]>)> {
    let n = (plaintext.len() / 16 + 1) as u32;

    let (blocks, remainder) = plaintext.as_chunks::<16>();

    let hash_key: [u8; 16] = (*block_cipher.encrypt(&[0; 16])).try_into()?;
    println!("H\t= {hash_key:02x?}");

    let y_0: [u8; 16] = if iv.len() == 12 {
        let mut x = [0; 16];
        x[..12].copy_from_slice(iv);
        x[12..].copy_from_slice(&1u32.to_be_bytes());
        x
    } else {
        // g_hash(&hash_key, &[], iv)
        todo!()
    };
    let e_y_0 = block_cipher.encrypt(&y_0);
    let get_y = |i| incr_by(y_0, i);

    println!("y_0\t= {:02x?}", y_0);
    println!("E(y_0)\t= {:02x?}", e_y_0);

    let mut ciphertext: Vec<u8> = Vec::new();

    for (i, p_i) in (1..).zip(blocks) {
        let y_i = get_y(i)?;
        println!("y_{i}\t= {y_i:02x?}");
        let e_k: [u8; 16] = (*block_cipher.encrypt(&y_i)).try_into()?;
        println!("E(y_{i})\t= {e_k:02x?}");

        let c_i = xor(*p_i, e_k);
        ciphertext.extend(c_i);
    }

    let e_k: [u8; 16] = (*block_cipher.encrypt(&get_y(n)?)).try_into()?;
    let p_n = remainder;
    let c_n = xor_dyn(p_n, &e_k[..(p_n.len())])?;
    ciphertext.extend(c_n);

    println!(
        "len\t= {:02x?}{:02x?}",
        ((additional_data.len() * 8) as u64).to_be_bytes(),
        ((ciphertext.len() * 8) as u64).to_be_bytes()
    );

    let ghash_hac = g_hash(&hash_key, additional_data, &ciphertext);
    println!("GHASH\t= {ghash_hac:02x?}");
    let tag = xor_dyn(&ghash_hac, &e_y_0)?;
    println!("T\t= {tag:02x?}");

    Ok((ciphertext.into_boxed_slice(), tag))
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
    fn test_mul() {
        // 0x0388dace60b6a392f328c2b971b2fe78 * 0x66e94bd4ef8a2c3b884cfa59ca342b2e
        // = 0x5e2ec746917062882c85b0685353deb7

        let a = 0x0388dace60b6a392f328c2b971b2fe78u128;
        let b = 0x66e94bd4ef8a2c3b884cfa59ca342b2eu128;
        let expected = 0x5e2ec746917062882c85b0685353deb7u128;

        let res = u128::from_be_bytes(mul_n(a.to_be_bytes(), b.to_be_bytes()));
        println!("= {res:016x}");

        assert_eq!(expected, res);
    }

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
                0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
                0xbd, 0xdf,
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
