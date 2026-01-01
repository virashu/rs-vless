use num_bigint::BigUint;

use crate::{hash::Hasher, utils::concat_dyn};

fn xor_dyn(a: &[u8], b: &[u8]) -> Box<[u8]> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

pub struct PublicKey {
    /// RSA modulus (n)
    modulus: BigUint,
    /// Public exponent (e)
    exponent: BigUint,
}

pub struct PrivateKey {
    /// RSA modulus (n)
    modulus: BigUint,
    /// Private exponent (d)
    exponent: BigUint,
}

/// Integer to Octet string
fn int_to_octets(value: &BigUint, len: usize) -> Box<[u8]> {
    let octets = value.to_bytes_be();
    let mut v = vec![0; len - octets.len()];
    v.extend(octets);
    v.into_boxed_slice()
}

/// Octet string to Integer
fn octets_to_int(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

/// (key, message) -> signature
fn rsa_sp1(key: &PrivateKey, msg_repr: &BigUint) -> BigUint {
    msg_repr.modpow(&key.exponent, &key.modulus)
}

/// (key, signature) -> message
fn rsa_vp1(key: &PublicKey, sgn_repr: &BigUint) -> BigUint {
    sgn_repr.modpow(&key.exponent, &key.modulus)
}

fn generate_mask<H: Hasher>(seed: &[u8], len: usize) -> Box<[u8]> {
    let mut t = Vec::new();

    for i in 0..len.div_ceil(H::DIGEST_SIZE) {
        let counter = (i as u32).to_be_bytes();
        let hash = H::hash(&{
            let mut acc = Vec::new();
            acc.extend(seed);
            acc.extend(counter);
            acc
        });
        t.extend(hash);
    }

    t.into_iter().take(len).collect()
}

fn emsa_pss_encode<H: Hasher>(salt_len: usize, message: &[u8], bits: usize) -> Box<[u8]> {
    let em_len = bits.div_ceil(8);
    let h_len = H::DIGEST_SIZE;

    let msg_hash = H::hash(message); // mHash
    let salt = rand::random_iter().take(salt_len).collect::<Box<[u8]>>();
    let msg_derived = concat_dyn![[0u8; 8], msg_hash, &salt]; // M'
    let msg_derived_hash = H::hash(&msg_derived); // H
    let padding = [0u8].repeat(em_len - salt_len - h_len - 2); // PS
    let db = concat_dyn![padding, [0x01], salt]; // DB
    let db_mask = generate_mask::<H>(&msg_derived_hash, em_len - h_len - 1); // dbMask
    let masked_db = xor_dyn(&db, &db_mask); // maskedDB

    // EM
    concat_dyn!(masked_db, msg_derived_hash, [0xbc])
}

fn emsa_pss_verify<H: Hasher>(
    salt_len: usize,
    message: &[u8],
    encoded_message: &[u8],
    bits: usize,
) -> bool {
    let em_len = bits.div_ceil(8);
    let h_len = H::DIGEST_SIZE;

    let msg_hash = H::hash(message); // mHash

    if em_len < h_len + salt_len + 2 {
        return false;
    }

    if *encoded_message.last().unwrap() != 0xbc {
        return false;
    }

    let (masked_db, msg_derived_hash) =
        encoded_message[..encoded_message.len() - 1].split_at(em_len - h_len - 1);

    let db_mask = generate_mask::<H>(msg_derived_hash, em_len - h_len - 1);
    let db = xor_dyn(masked_db, &db_mask); // D

    if db[..(em_len - salt_len - h_len - 2)]
        .iter()
        .any(|x| *x != 0)
    {
        return false;
    }

    let salt = &db[(db.len() - salt_len)..];
    let msg_derived = concat_dyn![[0u8; 8], &msg_hash, salt];
    let msg_derived_hash_derived = H::hash(&msg_derived);

    *msg_derived_hash == *msg_derived_hash_derived
}

#[allow(clippy::let_and_return)]
pub fn rsassa_pss_sign<H: Hasher>(key: &PrivateKey, message: &[u8]) -> Box<[u8]> {
    #[allow(clippy::cast_possible_truncation)]
    let mod_bits = key.modulus.bits() as usize;
    let mod_len = mod_bits.div_ceil(8);

    let encoded_message = emsa_pss_encode::<H>(20, message, mod_bits - 1);
    let msg_repr = octets_to_int(&encoded_message);
    let sgn_repr = rsa_sp1(key, &msg_repr);
    let signature = int_to_octets(&sgn_repr, mod_len);

    signature
}

pub fn rsassa_pss_verify<H: Hasher>(key: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    #[allow(clippy::cast_possible_truncation)]
    let mod_bits = key.modulus.bits() as usize;

    let sgn_repr = octets_to_int(signature);
    let msg_repr = rsa_vp1(key, &sgn_repr);
    let em_len = (mod_bits - 1).div_ceil(8);
    let encoded_message = int_to_octets(&msg_repr, em_len);

    emsa_pss_verify::<H>(20, message, &encoded_message, mod_bits - 1)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::hash::sha::Sha256;

    use super::*;

    #[test]
    fn test_signature() {
        let modulus = BigUint::from_bytes_be(&hex!(
            "bcb47b2e0dafcba81ff2a2b5cb115ca7e757184c9d72bcdcda707a146b3b4e29
             989ddc660bd694865b932b71ca24a335cf4d339c719183e6222e4c9ea6875acd
             528a49ba21863fe08147c3a47e41990b51a03f77d22137f8d74c43a5a45f4e9e
             18a2d15db051dc89385db9cf8374b63a8cc88113710e6d8179075b7dc79ee76b"
        ));
        let public_exponent = BigUint::from_bytes_be(&hex!(
            "0000000000000000000000000000000000000000000000000000000000000000
             0000000000000000000000000000000000000000000000000000000000000000
             0000000000000000000000000000000000000000000000000000000000000000
             0000000000000000000000000000000000000000000000000000000000010001"
        ));
        let private_exponent = BigUint::from_bytes_be(&hex!(
            "383a6f19e1ea27fd08c7fbc3bfa684bd6329888c0bbe4c98625e7181f411cfd0
             853144a3039404dda41bce2e31d588ec57c0e148146f0fa65b39008ba5835f82
             9ba35ae2f155d61b8a12581b99c927fd2f22252c5e73cba4a610db3973e019ee
             0f95130d4319ed413432f2e5e20d5215cdd27c2164206b3f80edee51938a25c1"
        ));

        let message = hex!(
            "1248f62a4389f42f7b4bb131053d6c88a994db2075b912ccbe3ea7dc611714f1
             4e075c104858f2f6e6cfd6abdedf015a821d03608bf4eba3169a6725ec422cd9
             069498b5515a9608ae7cc30e3d2ecfc1db6825f3e996ce9a5092926bc1cf61aa
             42d7f240e6f7aa0edb38bf81aa929d66bb5d890018088458720d72d569247b0c"
        );

        let signature = rsassa_pss_sign::<Sha256>(
            &PrivateKey {
                modulus: modulus.clone(),
                exponent: private_exponent,
            },
            &message,
        );
        assert!(rsassa_pss_verify::<Sha256>(
            &PublicKey {
                modulus: modulus.clone(),
                exponent: public_exponent.clone(),
            },
            &message,
            &signature,
        ));
        assert!(!rsassa_pss_verify::<Sha256>(
            &PublicKey {
                modulus,
                exponent: public_exponent,
            },
            &message,
            b"JHjklhasJGADSGLKJASDdkjhasD",
        ));
    }
}
