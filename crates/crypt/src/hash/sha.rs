use crate::hash::{
    Hasher,
    sha::constants::{INITIAL_SHA1, K_SHA_1},
};

pub mod constants;

fn ch_32(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn parity_32(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn maj_32(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

pub struct Sha1 {}
impl Hasher for Sha1 {
    const BLOCK_SIZE: usize = 64;
    const DIGEST_SIZE: usize = 20;

    fn hash(value: &[u8]) -> Box<[u8]> {
        let l_bytes = value.len();

        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let k_bytes = (56 - (l_bytes as i32 + 1)).rem_euclid(64) as usize;

        let message = {
            let mut x = Vec::new();
            x.extend(value);
            x.push(0b1000_0000);
            x.extend([0u8].repeat(k_bytes));
            x.extend(((l_bytes * 8) as u64).to_be_bytes());
            x
        };

        let blocks: Box<[[u32; 16]]> = message
            .chunks_exact(64)
            .map(|block| {
                (*block
                    .chunks_exact(4)
                    .map(|word| u32::from_be_bytes([word[0], word[1], word[2], word[3]]))
                    .collect::<Box<[u32]>>())
                .try_into()
                .unwrap()
            })
            .collect();

        let n_blocks = blocks.len();

        let mut hash = Vec::from([INITIAL_SHA1]);

        #[allow(clippy::many_single_char_names)]
        for i in 1..=n_blocks {
            // Prepare the message schedule
            let mut schedule: [u32; _] = [0; 80];
            schedule[..16].copy_from_slice(&blocks[i - 1]);
            for t in 16..80 {
                schedule[t] =
                    (schedule[t - 3] ^ schedule[t - 8] ^ schedule[t - 14] ^ schedule[t - 16])
                        .rotate_left(1);
            }

            // Initialize the five working variables
            let mut a = hash[i - 1][0];
            let mut b = hash[i - 1][1];
            let mut c = hash[i - 1][2];
            let mut d = hash[i - 1][3];
            let mut e = hash[i - 1][4];

            for t in 0..80 {
                let f = if (0..20).contains(&t) {
                    ch_32
                } else if (40..60).contains(&t) {
                    maj_32
                } else {
                    parity_32
                };

                let tt = a
                    .rotate_left(5)
                    .wrapping_add(f(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(K_SHA_1[t])
                    .wrapping_add(schedule[t]);

                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = tt;
            }

            let hash_value = [
                a.wrapping_add(hash[i - 1][0]),
                b.wrapping_add(hash[i - 1][1]),
                c.wrapping_add(hash[i - 1][2]),
                d.wrapping_add(hash[i - 1][3]),
                e.wrapping_add(hash[i - 1][4]),
            ];
            hash.push(hash_value);
        }

        hash[n_blocks]
            .iter()
            .flat_map(|word| word.to_be_bytes())
            .collect()
    }
}

pub struct Sha256 {}
impl Hasher for Sha256 {
    const BLOCK_SIZE: usize = 64;
    const DIGEST_SIZE: usize = 32;

    fn hash(value: &[u8]) -> Box<[u8]> {
        todo!()
    }
}

pub struct Sha384 {}
impl Hasher for Sha384 {
    const BLOCK_SIZE: usize = 128;
    const DIGEST_SIZE: usize = 48;

    fn hash(value: &[u8]) -> Box<[u8]> {
        todo!()
    }
}

pub struct Sha512 {}
impl Hasher for Sha512 {
    const BLOCK_SIZE: usize = 128;
    const DIGEST_SIZE: usize = 64;

    fn hash(value: &[u8]) -> Box<[u8]> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1() {
        let input = b"abc";
        let output = Sha1::hash(input);

        assert_eq!(
            *output,
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ],
        );
    }
}
