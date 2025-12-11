use anyhow::{Result, bail};

use crate::aes::{Aes, Aes256Cipher};

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

#[allow(clippy::many_single_char_names)]
fn x_i(
    (n, u, m, v, i): (u32, u32, u32, u32, u32),
    hash_key: &[u8; 16],
    a: &[[u8; 16]],
    c: &[[u8; 16]],
) -> [u8; 16] {
    let x = |i| x_i((n, u, m, v, i), hash_key, a, c);

    match i {
        0 => [0; 16],

        _ if (1..m).contains(&i) => mul(xor(x(i - 1), a[i as usize - 1]), *hash_key),

        _ if m == i => mul(xor(x(m - 1), a[m as usize - 1]), *hash_key),

        _ if ((m + 1)..(m + n)).contains(&i) => mul(xor(x(i - 1), c[i as usize - 1]), *hash_key),

        _ if m + n == i => mul(
            xor(
                x(m + n - 1),
                if m != 0 { c[m as usize - 1] } else { [0; 16] },
            ),
            *hash_key,
        ),

        _ if m + n + 1 == i => {
            let a_len: [u8; 8] = u64::from(m + v).to_be_bytes();
            let c_len: [u8; 8] = u64::from(n + u).to_be_bytes();
            let len: [u8; 16] = [a_len, c_len].concat().try_into().unwrap();
            mul(xor(x(m + n), len), *hash_key)
        }

        _ => unimplemented!(),
    }
}

#[allow(clippy::many_single_char_names)]
fn g_hash(hash_key: &[u8; 16], a: &[u8], c: &[u8]) -> [u8; 16] {
    // Ciphertext
    let c_bits = c.len() * 8;
    let n = (c_bits / 128) as u32;
    let u = (c_bits % 128) as u32;
    let c_padded = if u == 0 {
        Vec::from(c)
    } else {
        let mut c = Vec::from(a);
        c.extend(vec![0; (u / 8) as usize]);
        c
    };
    let c_blocks = c_padded.as_chunks::<16>().0;

    // Additional data
    let a_bits = a.len() * 8;
    let m = (a_bits / 128) as u32;
    let v = (a_bits % 128) as u32;
    let a_padded = if v == 0 {
        Vec::from(a)
    } else {
        let mut a = Vec::from(a);
        a.extend(vec![0; (v / 8) as usize]);
        a
    };
    let a_blocks = a_padded.as_chunks::<16>().0;

    x_i((n, u, m, v, m + n + 1), hash_key, a_blocks, c_blocks)
}

#[allow(clippy::type_complexity)]
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::missing_errors_doc)]
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::many_single_char_names)]
pub fn encrypt(
    secret: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
) -> Result<(Box<[u8]>, Box<[u8]>)> {
    let p_bits = plaintext.len() * 8;
    let n = (p_bits / 128) as u32;

    let (blocks, remainder) = plaintext.as_chunks::<16>();

    let aes = Aes::new(Aes256Cipher::new(secret.try_into()?));

    let hash_key: [u8; 16] = (*aes.encrypt(&[0; 16])).try_into()?;

    let y_0: [u8; 16] = if iv.len() == 12 {
        let mut x = [0; 16];
        x[..12].copy_from_slice(iv);
        x[12..].copy_from_slice(&1u32.to_be_bytes());
        x
    } else {
        g_hash(&hash_key, &[], iv)
    };
    let y_i = |i| incr_by(y_0, i);

    let mut ciphertext: Vec<u8> = Vec::new();

    for (i, p_i) in (1..).zip(blocks) {
        let e_k: [u8; 16] = (*aes.encrypt(&y_i(i)?)).try_into()?;
        let c_i = xor(*p_i, e_k);
        ciphertext.extend(c_i);
    }

    let e_k: [u8; 16] = (*aes.encrypt(&y_i(n)?)).try_into()?;
    let p_n = remainder;
    let c_n = xor_dyn(p_n, &e_k[..(p_n.len())])?;
    ciphertext.extend(c_n);

    let tag = g_hash(&hash_key, additional_data, &ciphertext);

    Ok((ciphertext.into_boxed_slice(), Box::new(tag)))
}
