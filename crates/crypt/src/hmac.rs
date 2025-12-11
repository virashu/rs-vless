use crate::hash::Hasher;

pub fn hmac_hash<H: Hasher>(key: &[u8], text: &[u8]) -> Box<[u8]> {
    // let key = {
    //     let mut x = vec![0; H::BLOCK_SIZE];
    //     x.copy_from_slice(key);
    //     x
    // };

    let text_1 = {
        let mut x = vec![0x36; H::BLOCK_SIZE];
        key.iter().enumerate().for_each(|(i, k)| x[i] ^= k);
        x.extend(text);
        x
    };
    let hashsum_1 = H::hash(&text_1);

    let text_2 = {
        let mut x = vec![0x5c; H::BLOCK_SIZE];
        key.iter().enumerate().for_each(|(i, k)| x[i] ^= k);
        x.extend(hashsum_1);
        x
    };
    H::hash(&text_2)
}
