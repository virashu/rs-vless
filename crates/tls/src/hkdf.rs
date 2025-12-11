use crypt::{hash::Hasher, hmac::hmac_hash};

pub fn hkdf_extract<H: Hasher>(salt: &[u8], ikm: &[u8]) -> Box<[u8]> {
    hmac_hash::<H>(salt, ikm)
}

pub fn hkdf_expand<H: Hasher>(prk: &[u8], info: &[u8], length: usize) -> Box<[u8]> {
    let n = length.div_ceil(H::DIGEST_SIZE);
    let mut t: Vec<Box<[u8]>> = Vec::from([Box::from(&[] as &[u8])]);

    for i in 1..=n {
        let concatd = {
            let mut x = Vec::new();
            x.extend(&t[i - 1]);
            x.extend(info);
            #[allow(clippy::cast_possible_truncation)]
            x.push(i as u8);
            x.into_boxed_slice()
        };

        let t_i = hmac_hash::<H>(prk, &concatd);
        t.push(t_i);
    }

    t.into_iter().flatten().take(length).collect()
}

pub fn hkdf_expand_label<H: Hasher>(
    secret: &[u8],
    label: impl AsRef<str>,
    context: &[u8],
    length: u16,
) -> Box<[u8]> {
    let hkdf_label = {
        let mut x = Vec::new();
        x.extend(length.to_be_bytes());
        x.extend(b"tls13 ");
        x.extend(label.as_ref().as_bytes());
        x.extend(context);
        x.into_boxed_slice()
    };

    hkdf_expand::<H>(secret, &hkdf_label, length as usize)
}

// pub fn transcript_hash(_: &[u8]) -> Vec<u8> {
//     todo!()
// }

pub fn derive_secret<H: Hasher>(
    secret: &[u8],
    label: impl AsRef<str>,
    messages: &[u8],
) -> Box<[u8]> {
    let context = H::hash(messages);
    let length = context.len() as u16;

    hkdf_expand_label::<H>(secret, label, &context, 32)
}
