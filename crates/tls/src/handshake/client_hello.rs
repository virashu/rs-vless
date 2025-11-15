use anyhow::{Result, bail};

use std::sync::Arc;

use crate::{
    CipherSuite,
    handshake::extension::Extension,
    util::{opaque_vec_8, opaque_vec_16},
};

#[derive(Debug)]
pub struct ClientHello {
    pub random: Box<[u8; 32]>,
    pub legacy_session_id: Box<[u8]>,
    pub cipher_suites: Box<[CipherSuite]>,
    pub legacy_compression_methods: Box<[u8]>,
    pub extensions: Box<[Extension]>,
}

impl ClientHello {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let mut offset: usize = 0;

        let legacy_version = u16::from_be_bytes([raw[0], raw[1]]);
        if legacy_version != 0x0303 {
            bail!("Invalid legacy version: {legacy_version} (should be equal 0x0303)");
        }
        offset += 2;

        let random = Box::new(raw[(offset)..(offset + 32)].try_into()?);
        offset += 32;

        let (size, legacy_session_id) = opaque_vec_8(&raw[offset..]);
        offset += size;

        // let cipher_suites_length = u16::from_be_bytes([raw[offset], raw[offset + 1]]) as usize;
        // offset += 2;
        // let cipher_suites = raw[offset..(offset + cipher_suites_length)]
        //     .chunks(2)
        //     .map(|x| CipherSuite {
        //         aead_algorithm: x[0],
        //         hkdf_hash: x[1],
        //     })
        //     .collect();
        // offset += cipher_suites_length;

        let (size, cipher_suites_raw) = opaque_vec_16(&raw[offset..]);
        offset += size;
        let cipher_suites = cipher_suites_raw
            .chunks(2)
            .map(|x| CipherSuite {
                aead_algorithm: x[0],
                hkdf_hash: x[1],
            })
            .collect();

        let (size, legacy_compression_methods) = opaque_vec_8(&raw[offset..]);
        offset += size;

        let (_, extensions_raw) = opaque_vec_16(&raw[offset..]);

        // Parse extensions
        let total_length = extensions_raw.len();
        let mut parsed_length = 0;
        let mut extensions = Vec::new();
        while parsed_length < total_length {
            match Extension::from_raw(&extensions_raw[parsed_length..]) {
                Ok(ext) => {
                    parsed_length += ext.size();
                    extensions.push(ext);
                }
                Err(err) => {
                    tracing::warn!("Failed to parse extension: {err}");
                    parsed_length += Extension::size_raw(&extensions_raw[parsed_length..]);
                }
            }
        }

        if parsed_length != total_length {
            tracing::error!("Unparsed extensions parts left ({parsed_length}/{total_length})");
        }

        Ok(Self {
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods,
            extensions: extensions.into_boxed_slice(),
        })
    }
}
