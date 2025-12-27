use hex_literal::hex;
use num_bigint::BigUint;

pub fn poly1305_mac(msg: &[u8], key: [u8; 32]) -> [u8; 16] {
    let r = BigUint::from_bytes_le(&key[0..16]);
    let r = r & BigUint::from(0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffffu128);
    let s = BigUint::from_bytes_le(&key[16..32]);
    let mut acc = BigUint::ZERO;
    let p = BigUint::from_bytes_be(&hex!("03fffffffffffffffffffffffffffffffb"));

    for chunk in msg.chunks(16) {
        let bytes = {
            let mut x = Vec::new();
            x.extend(chunk);
            x.push(0x01);
            x
        };
        let n = BigUint::from_bytes_le(&bytes);
        acc += n;
        acc = (&r * acc) % &p;
    }

    acc += s;

    acc.to_bytes_le()[..16].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly1305_mac() {
        let key = hex!(
            "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8
            :01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b"
        );
        let message = b"Cryptographic Forum Research Group";

        assert_eq!(
            poly1305_mac(message, key),
            hex!("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9")
        );
    }
}
