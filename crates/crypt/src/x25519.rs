mod scalar;
use scalar::Scalar;

use bnum::BUintD8;

type ScalarInner = BUintD8<32>;

// const A1: u256 = u256::parse_str_radix("486662", 10);
const A24: Scalar = Scalar::raw(ScalarInner::parse_str_radix("121665", 10));
const BASE: Scalar = Scalar::raw(ScalarInner::NINE);

type PrivateKey = [u8; 32];
type PublicKey = [u8; 32];
type SharedKey = [u8; 32];

#[allow(clippy::many_single_char_names, clippy::similar_names)]
fn x25519(scalar: Scalar, point: Scalar) -> Scalar {
    let x_1 = point;

    let mut x_2 = Scalar::from(1u32);
    let mut z_2 = Scalar::from(0u32);

    let mut x_3 = point;
    let mut z_3 = Scalar::from(1u32);

    let mut swap = false;

    // Montgomery ladder
    for t in (0..255).rev() {
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

    x_2 * z_2.inv()
}

pub fn get_keypair() -> (PublicKey, PrivateKey) {
    let mut private_key = [0; 32];
    rand::fill(&mut private_key);

    (get_public_key(private_key), private_key)
}

pub fn get_public_key(private_key: PrivateKey) -> PublicKey {
    x25519(Scalar::from_bytes(private_key), BASE).into_bytes()
}

pub fn get_shared_key(private_key: PrivateKey, peer_public_key: PublicKey) -> SharedKey {
    x25519(
        Scalar::from_bytes(private_key),
        Scalar::from_bytes(peer_public_key),
    )
    .into_bytes()
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
        let point = ScalarInner::parse_str_radix(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            16,
        );
        let expected = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d,
            0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55,
            0x77, 0xa2, 0x85, 0x52,
        ];

        let out = x25519(Scalar::from(scalar), Scalar::from(point)).into_bytes();

        assert_eq!(out, expected);
    }

    #[test]
    fn test_diffie_hellman() {
        let alice_private = ScalarInner::parse_str_radix(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            16,
        );
        let alice_public = ScalarInner::parse_str_radix(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            16,
        );
        let bob_private = ScalarInner::parse_str_radix(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
            16,
        );
        let bob_public = ScalarInner::parse_str_radix(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
            16,
        );
        let shared = ScalarInner::parse_str_radix(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
            16,
        );

        assert_eq!(
            get_public_key(*alice_private.digits()),
            *alice_public.digits()
        );

        assert_eq!(get_public_key(*bob_private.digits()), *bob_public.digits());

        assert_eq!(
            get_shared_key(*alice_public.digits(), *bob_public.digits()),
            *shared.digits()
        );
    }

    #[test]
    fn test_n_calls() {
        let iter_1 = ScalarInner::parse_str_radix(
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
            16,
        );
        let iter_1k = ScalarInner::parse_str_radix(
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
            16,
        );
        let iter_1m = ScalarInner::parse_str_radix(
            "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424",
            16,
        );

        let mut scalar = Scalar::raw(ScalarInner::parse_str_radix(
            "0900000000000000000000000000000000000000000000000000000000000000",
            16,
        ));
        let point = scalar;

        scalar = x25519(scalar, point);

        assert_eq!(scalar.into_inner(), iter_1);

        for _ in 0..1000 {
            scalar = x25519(scalar, point);
        }

        assert_eq!(scalar.into_inner(), iter_1k);

        for _ in 0..1_000_000 {
            scalar = x25519(scalar, point);
        }

        assert_eq!(scalar.into_inner(), iter_1m);
    }

    #[test]
    fn test_inv() {
        for k in 1..5 {
            let a = Scalar::from(k);
            let b = a.inv();

            dbg!(a);
            dbg!(b);

            // b = 2^254 - 9
            assert_eq!((a * b).into_inner(), ScalarInner::ONE);
        }
    }

    #[test]
    fn test_exchange() {
        let (alice_public, alice_private) = get_keypair();

        let (bob_public, bob_private) = get_keypair();

        let alice_shared = get_shared_key(alice_private, bob_public);
        let bob_shared = get_shared_key(bob_private, alice_public);

        assert_eq!(alice_shared, bob_shared);
    }
}
