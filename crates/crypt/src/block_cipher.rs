pub mod aes;

pub trait BlockCipher {
    fn encrypt(&self, value: &[u8]) -> Box<[u8]>;
}
