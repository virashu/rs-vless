fn xor(mut a: [u8; 64], b: [u8; 64]) -> [u8; 64] {
    for i in 0..64 {
        a[i] ^= b[i];
    }
    a
}

fn quartet_round(values: [u32; 4]) -> [u32; 4] {
    let mut a = values[0];
    let mut b = values[1];
    let mut c = values[2];
    let mut d = values[3];

    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(16);

    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(12);

    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(8);

    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(7);

    [a, b, c, d]
}

fn inner_block(mut state: [u32; 16]) -> [u32; 16] {
    macro_rules! q_round {
        ($a:literal, $b:literal, $c:literal, $d:literal) => {{
            let [a, b, c, d] = quartet_round([state[$a], state[$b], state[$c], state[$d]]);
            state[$a] = a;
            state[$b] = b;
            state[$c] = c;
            state[$d] = d;
        }};
    }

    q_round!(0, 4, 8, 12);
    q_round!(1, 5, 9, 13);
    q_round!(2, 6, 10, 14);
    q_round!(3, 7, 11, 15);
    q_round!(0, 5, 10, 15);
    q_round!(1, 6, 11, 12);
    q_round!(2, 7, 8, 13);
    q_round!(3, 4, 9, 14);

    state
}

const CHACHA20_INIT: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

pub(crate) fn chacha20_block(key: [u8; 32], counter: u32, nonce: [u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0..4].copy_from_slice(&CHACHA20_INIT);

    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }

    state[12] = counter;

    state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

    println!("{state:08x?}");
    let initial_state = state;

    for _ in 0..10 {
        state = inner_block(state);
    }

    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial_state[i]);
    }
    println!("{state:08x?}");

    // Serialization
    let mut res = [0u8; 64];
    for i in 0..16 {
        res[(i * 4)..(i * 4 + 4)].copy_from_slice(&state[i].to_le_bytes());
    }
    res
}

pub fn chacha20_encrypt(
    key: [u8; 32],
    counter: u32,
    nonce: [u8; 12],
    plaintext: &[u8],
) -> Box<[u8]> {
    let (blocks, remainder) = plaintext.as_chunks::<64>();

    let mut encrypted = Vec::new();

    for (block, j) in blocks.iter().zip(0u32..) {
        let key_stream = chacha20_block(key, counter + j, nonce);
        println!("{key_stream:02x?}");
        encrypted.extend(xor(*block, key_stream));
    }

    if !remainder.is_empty() {
        #[allow(clippy::cast_possible_truncation)]
        let j = (plaintext.len() / 64) as u32;
        let key_stream = chacha20_block(key, counter + j, nonce);
        println!("{key_stream:02x?}");
        encrypted.extend(remainder.iter().zip(key_stream).map(|(a, b)| a ^ b));
    }

    encrypted.into_boxed_slice()
}
#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    /// <https://datatracker.ietf.org/doc/html/rfc8439#section-2.1.1>
    #[test]
    fn test_quartet_round() {
        let input = [0x1111_1111, 0x0102_0304, 0x9b8d_6f43, 0x0123_4567];
        let output = [0xea2a_92f4, 0xcb1c_f8ce, 0x4581_472e, 0x5881_c4bb];
        assert_eq!(quartet_round(input), output);
    }

    /// <https://datatracker.ietf.org/doc/html/rfc8439#section-2.3.2>
    #[test]
    fn test_chacha20_block() {
        let key = hex!(
            "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f
            :10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
        );
        let nonce = hex!("00:00:00:09:00:00:00:4a:00:00:00:00");
        let block_count = 1;

        let output = hex!(
            "10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4
             c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e
             d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2
             b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e"
        );

        assert_eq!(chacha20_block(key, block_count, nonce), output);
    }

    #[test]
    fn test_chacha20_encrypt() {
        let key = hex!(
            "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f
            :10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
        );
        let nonce = hex!("00:00:00:00:00:00:00:4a:00:00:00:00");
        let initial_counter = 1;

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could \
            offer you only one tip for the future, sunscreen would be it.";
        let output = hex!(
            "6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
             e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
             f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
             16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
             07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
             52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
             5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
             87 4d"
        );

        assert_eq!(
            *chacha20_encrypt(key, initial_counter, nonce, plaintext),
            output
        );
    }
}
