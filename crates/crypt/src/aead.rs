use anyhow::{Result, bail};

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
    if a.len() != b.len() {
        bail!("Len is not equal");
    }

    Ok(a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect())
}

fn shr(x: [u8; 16]) -> [u8; 16] {
    (u128::from_be_bytes(x) >> 1).to_be_bytes()
}

// fn mul(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
//     (u128::from_be_bytes(a).wrapping_mul(u128::from_be_bytes(b))).to_be_bytes()
// }

fn mul(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    const R: [u8; 16] = (0b_1110_0001_u128 << 120).to_be_bytes();

    let mut z = [0; 16];
    let mut v = x;

    for i in 0..128 {
        let y_i = y[i / 8] >> (7 - (i % 8));

        if y_i == 1 {
            z = xor(z, v);
        }

        if v[15] >> 7 == 0 {
            v = shr(v);
        } else {
            v = xor(shr(v), R);
        }
    }

    z
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

// #[allow(clippy::many_single_char_names)]
// fn x_i(
//     (n, u, m, v, i): (usize, usize, usize, usize, usize),
//     hash_key: &[u8; 16],
//     a: &[[u8; 16]],
//     a_rem: &[u8],
//     c: &[[u8; 16]],
//     c_rem: &[u8],
// ) -> [u8; 16] {
//     let x = |i| x_i((n, u, m, v, i), hash_key, a, a_rem, c, c_rem);

//     let r = match i {
//         0 => [0; 16],

//         _ if (1..m).contains(&i) => mul(xor(x(i - 1), a[i - 1]), *hash_key),

//         _ if m == i => mul(
//             xor(x(i - 1), {
//                 let mut pad = [0; 16];
//                 pad[..a_rem.len()].copy_from_slice(a_rem);
//                 pad
//             }),
//             *hash_key,
//         ),

//         _ if ((m + 1)..(m + n)).contains(&i) => {
//             dbg!(m, n, i);
//             mul(xor(x(i - 1), c[i - 1 - m]), *hash_key)
//         }

//         _ if m + n == i => mul(
//             xor(x(i - 1), {
//                 let mut pad = [0; 16];
//                 pad[..c_rem.len()].copy_from_slice(c_rem);
//                 pad
//             }),
//             *hash_key,
//         ),

//         _ if m + n + 1 == i => {
//             let a_len: [u8; 8] = (((m - 1) * 128 + v) as u64).to_be_bytes();
//             let c_len: [u8; 8] = (((n - 1) * 128 + u) as u64).to_be_bytes();
//             let len: [u8; 16] = [a_len, c_len].concat().try_into().unwrap();
//             mul(xor(x(m + n), len), *hash_key)
//         }

//         _ => unimplemented!(),
//     };
//     println!("x_{i}\t= {r:02x?}");
//     r
// }

// #[allow(clippy::many_single_char_names)]
// fn g_hash(hash_key: &[u8; 16], a: &[u8], c: &[u8]) -> [u8; 16] {
//     // Ciphertext
//     let n = c.len() / 16 + 1;
//     let u = c.len() % 16 * 8;
//     let c_padded = if u == 0 {
//         Vec::from(c)
//     } else {
//         let mut c = Vec::from(a);
//         c.extend(vec![0; 16 - (u / 8)]);
//         c
//     };

//     let (c_blocks, c_remainder) = c_padded.as_chunks::<16>();

//     // Additional data
//     let m = a.len() / 16 + 1;
//     let v = a.len() % 16 * 8;
//     let a_padded = if v == 0 {
//         Vec::from(a)
//     } else {
//         let mut a = Vec::from(a);
//         a.extend(vec![0; 16 - (v / 8)]);
//         a
//     };
//     let (a_blocks, a_remainder) = a_padded.as_chunks::<16>();

//     let i = m + n + 1;
//     x_i(
//         (n, u, m, v, i),
//         hash_key,
//         a_blocks,
//         a_remainder,
//         c_blocks,
//         c_remainder,
//     )
// }

fn g_hash(hash_key: &[u8; 16], a: &[u8], c: &[u8]) -> [u8; 16] {
    let blocks = {
        let mut acc = Vec::new();

        let (a_blocks, a_remainder) = a.as_chunks::<16>();
        acc.extend(a_blocks);
        acc.push({
            let mut pad = [0; 16];
            pad[..a_remainder.len()].copy_from_slice(a_remainder);
            pad
        });

        let (c_blocks, c_remainder) = c.as_chunks::<16>();
        acc.extend(c_blocks);
        acc.push({
            let mut pad = [0; 16];
            pad[..c_remainder.len()].copy_from_slice(c_remainder);
            pad
        });

        acc.push({
            let a_len: [u8; 8] = ((a.len() * 8) as u64).to_be_bytes();
            let c_len: [u8; 8] = ((c.len() * 8) as u64).to_be_bytes();
            [a_len, c_len].concat().try_into().unwrap()
        });

        acc
    };

    let mut x = [0; 16];

    for (block, i) in blocks.into_iter().zip(1..) {
        x = mul(xor(x, block), *hash_key);
        println!("BLOCK #{i}: {block:02x?}");
        println!("X_{i}\t= {x:02x?}");
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
    let u = (plaintext.len() % 16 * 8) as u32;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_sha_128_gcm_1() {
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
    fn test_aead_sha_128_gcm_2() {
        let key = [0; 16];
        let iv = [0; 12];
        let plaintext = [0; 16];
        let ad = [];

        let m = mul(2u128.to_be_bytes(), 2u128.to_be_bytes());
        dbg!(m);

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

    #[test]
    fn test_aead_sha_128_gcm_3() {
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

    #[test]
    fn test_aead_sha_256_gcm_1() {
        let key = [0; 32];
        let iv = [0; 12];
        let plaintext = [];
        let ad = [];

        let (c, t) = encrypt_aes_256_gcm(&key, &iv, &plaintext, &ad).unwrap();

        assert_eq!(*c, []);
        assert_eq!(
            *t,
            [
                0xcd, 0x33, 0xb2, 0x8a, 0xc7, 0x73, 0xf7, 0x4b, 0xa0, 0x0e, 0xd1, 0xf3, 0x12, 0x57,
                0x24, 0x35,
            ]
        );
    }
}
