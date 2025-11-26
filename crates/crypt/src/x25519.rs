mod scalar;

pub use scalar::Scalar;

use bnum::BUintD8;

type ScalarInner = BUintD8<32>;

// const A1: u256 = u256::parse_str_radix("486662", 10);
const A24: Scalar = Scalar::raw(ScalarInner::parse_str_radix("121665", 10));
const BASE: Scalar = Scalar::raw(ScalarInner::NINE);

type PrivateKey = [u8; 32];
type PublicKey = [u8; 32];
type SharedKey = [u8; 32];

#[allow(clippy::many_single_char_names, clippy::similar_names)]
fn x25519(private_key: PrivateKey, point: Scalar) -> PublicKey {
    let scalar = Scalar::from_bytes(private_key);

    let x_1 = point;
    let mut x_2 = Scalar::from(1u32);
    let mut z_2 = Scalar::from(0u32);
    let mut x_3 = point;
    let mut z_3 = Scalar::from(1u32);
    let mut swap = false;

    // Montgomery ladder
    for t in (0..=255u32).rev() {
        let k_t = (scalar.into_inner() >> t) & ScalarInner::ONE == ScalarInner::ONE;
        swap ^= k_t;
        (x_2, x_3) = if swap { (x_3, x_2) } else { (x_2, x_3) };
        (z_2, z_3) = if swap { (z_3, z_2) } else { (z_2, z_3) };
        swap = k_t;

        let a = x_2 + z_2;
        let aa = a.sq();

        let b = x_2 - z_2;
        let bb = b.sq();

        let e = aa - bb;
        let c = x_3 + z_3;
        let d = x_3 - z_3;

        let da = d * a;
        let cb = c * b;

        x_3 = (da + cb).sq();
        z_3 = x_1 * (da - cb).sq();

        x_2 = aa * bb;
        z_2 = e * (aa + (A24 * e));
    }

    (x_2, _) = if swap { (x_3, x_2) } else { (x_2, x_3) };
    (z_2, _) = if swap { (z_3, z_2) } else { (z_2, z_3) };

    let res = x_2 * z_2.inv();
    res.into_bytes()
}

pub fn get_keypair() -> (PublicKey, PrivateKey) {
    let mut private_key = [0; 32];
    rand::fill(&mut private_key);

    (get_public_key(private_key), private_key)
}

fn get_public_key(private_key: PrivateKey) -> PublicKey {
    x25519(private_key, BASE)
}

fn get_shared_key(private_key: PrivateKey, peer_public_key: PublicKey) -> SharedKey {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen() {
        let scalar = ScalarInner::parse_str_radix(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            16,
        );
        let key = ScalarInner::parse_str_radix(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            16,
        );
        let te = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d,
            0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55,
            0x77, 0xa2, 0x85, 0x52,
        ];

        let out = x25519(*key.digits(), Scalar::from(scalar));

        assert_eq!(out, te);
    }

    #[test]
    fn test_inv() {
        let a = Scalar::from(2);
        let b = a.inv();

        dbg!(a);
        dbg!(b);

        // b = 2^254 - 9
        assert_eq!((a * b).into_inner(), ScalarInner::ONE);
    }
}
