use crate::{
    aead::poly1305::poly1305_mac,
    symmetric::chacha20::{chacha20_block, chacha20_encrypt},
};

fn poly1305_key_gen(key: [u8; 32], nonce: [u8; 12]) -> [u8; 32] {
    let block = chacha20_block(key, 0, nonce);
    block[0..32].try_into().unwrap()
}

pub fn encrypt_chacha20_poly1305(
    key: [u8; 32],
    iv: [u8; 12],
    plaintext: &[u8],
    additional_data: &[u8],
) -> (Box<[u8]>, [u8; 16]) {
    //     nonce = constant | iv
    let otk = poly1305_key_gen(key, iv);
    let ciphertext = chacha20_encrypt(key, 1, iv, plaintext);

    let mut mac_data = Vec::new();

    mac_data.extend(additional_data);
    mac_data.extend([0].repeat(mac_data.len().div_ceil(16) * 16 - mac_data.len()));

    mac_data.extend(&ciphertext);
    mac_data.extend([0].repeat(mac_data.len().div_ceil(16) * 16 - mac_data.len()));

    mac_data.extend((additional_data.len() as u64).to_le_bytes());
    mac_data.extend((ciphertext.len() as u64).to_le_bytes());

    let tag = poly1305_mac(&mac_data, otk);

    (ciphertext, tag)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn test_aead_chacha20_poly1305() {
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could \
            offer you only one tip for the future, sunscreen would be it.";
        let additional_data = hex!("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7");
        let key = hex!(
            "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f
             90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f"
        );
        let iv = hex!("07 00 00 00 40 41 42 43 44 45 46 47");

        let tag = hex!("1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91");

        assert_eq!(
            encrypt_chacha20_poly1305(key, iv, plaintext, &additional_data).1,
            tag
        );
    }
}
