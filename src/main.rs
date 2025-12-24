use anyhow::{Result, anyhow, bail};
use crypt::{elliptic::x25519, hash::sha::Sha384};
use tls::{
    cipher_suite::TLS_AES_256_GCM_SHA384,
    error::TlsAlert,
    hkdf::{derive_secret, hkdf_expand_label, hkdf_extract},
    record::{
        TlsCiphertext, TlsContent, TlsPlaintext,
        handshake::{
            Handshake,
            certificate::Certificate,
            certificate_request::{CertificateRequest, CertificateRequestExtension},
            encrypted_extensions::EncryptedExtensions,
            extension::{KeyShareEntry, NamedGroup, SignatureScheme},
            server_hello::{ServerHello, ServerHelloExtension},
        },
    },
};

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::organized_extensions::OrganizedClientExtensions;

mod organized_extensions;

fn xor<const N: usize>(mut a: [u8; N], b: [u8; N]) -> [u8; N] {
    for i in 0..N {
        a[i] ^= b[i];
    }
    a
}

struct TlsContext {
    key_ecdhe: Option<Box<[u8]>>,
    key_psk: Option<Box<[u8]>>,

    seq_nonce: AtomicU64,
}

impl TlsContext {
    pub fn new(key_ecdhe: Option<Box<[u8]>>, key_psk: Option<Box<[u8]>>) -> Self {
        Self {
            key_ecdhe,
            key_psk,
            seq_nonce: AtomicU64::new(0),
        }
    }

    pub fn key_ecdhe(&self) -> &[u8] {
        self.key_ecdhe.as_deref().unwrap_or(&[0; 32])
    }

    pub fn key_psk(&self) -> &[u8] {
        self.key_psk.as_deref().unwrap_or(&[0; 48])
    }

    pub fn nonce(&self) -> u64 {
        self.seq_nonce.fetch_add(1, Ordering::Relaxed)
    }

    pub fn pad_nonce<const L: usize>(&self) -> [u8; L] {
        let mut x = [0; L];
        x[..8].copy_from_slice(&self.nonce().to_be_bytes());
        x
    }
}

fn handshake(conn: &mut TcpStream) -> Result<()> {
    const VERSION: u16 = 0x0304;

    let mut buf = [0; 2800];
    let n = conn.read(&mut buf)?;

    // ClientHello

    let ch_raw = &buf[..n];
    let ch_record = TlsPlaintext::from_raw(ch_raw)?;
    let TlsContent::Handshake(Handshake::ClientHello(client_hello)) = ch_record.fragment else {
        bail!("Not client hello");
    };
    let ch_exts = OrganizedClientExtensions::organize(client_hello.extensions);

    let extended = ch_exts.extended_main_secret.is_some();

    // EC-DHE

    let key_share = ch_exts
        .key_share
        .ok_or(anyhow!("Missing key_share"))?
        .to_hashmap();

    let x25519_public;
    let x25519_shared;

    if let Some(share) = key_share.get(&NamedGroup::x25519) {
        let (public, private) = x25519::get_keypair();

        x25519_public = Some(public);
        x25519_shared = Some(x25519::get_shared_key(private, share.as_ref().try_into()?));
    } else {
        x25519_public = None;
        x25519_shared = None;
    }

    let flag_psk = false;

    let context = TlsContext::new(x25519_shared.map(Box::from), None);

    // ServerHello

    let mut sh_extensions = Vec::from([ServerHelloExtension::new_supported_versions(VERSION)]);

    if let Some(share) = &x25519_public {
        sh_extensions.push(ServerHelloExtension::new_key_share(KeyShareEntry::new(
            NamedGroup::x25519,
            share,
        ))?);
    }

    if flag_psk {
        sh_extensions.push(ServerHelloExtension::new_pre_shared_key(0));
    }

    let server_hello = Handshake::ServerHello(ServerHello::new(
        &rand::random(),
        &client_hello.legacy_session_id,
        TLS_AES_256_GCM_SHA384,
        &sh_extensions,
    ));
    let sh_record = TlsPlaintext::new_handshake(server_hello)?;
    let sh_raw = sh_record.to_raw();
    conn.write_all(&sh_raw)?;

    // Key schedule

    let early_secret = hkdf_extract::<Sha384>(&[0; 48], context.key_psk());

    let handshake_secret = hkdf_extract::<Sha384>(
        &derive_secret::<Sha384>(&early_secret, "derived", &[]),
        context.key_ecdhe(),
    );

    let transcript = {
        let mut x = Vec::new();
        x.extend(&ch_raw[5..]);
        x.extend(&sh_raw[5..]);
        x.into_boxed_slice()
    };

    // Server keys
    let server_handshake_traffic_secret: [u8; 48] =
        derive_secret::<Sha384>(&handshake_secret, "s hs traffic", &transcript)
            .as_ref()
            .try_into()?;
    let server_write_key: [u8; 32] =
        hkdf_expand_label::<Sha384>(&server_handshake_traffic_secret, "key", &[], 32)
            .as_ref()
            .try_into()?;
    let server_write_iv: [u8; 12] =
        hkdf_expand_label::<Sha384>(&server_handshake_traffic_secret, "iv", &[], 12)
            .as_ref()
            .try_into()?;

    // Client keys
    let client_handshake_traffic_secret: [u8; 48] =
        derive_secret::<Sha384>(&handshake_secret, "c hs traffic", &transcript)
            .as_ref()
            .try_into()?;
    let client_write_key: [u8; 32] =
        hkdf_expand_label::<Sha384>(&client_handshake_traffic_secret, "key", &[], 32)
            .as_ref()
            .try_into()?;
    let client_write_iv: [u8; 12] =
        hkdf_expand_label::<Sha384>(&client_handshake_traffic_secret, "iv", &[], 12)
            .as_ref()
            .try_into()?;

    let main_secret = hkdf_extract::<Sha384>(
        &derive_secret::<Sha384>(&handshake_secret, "derived", &[]),
        &[0; 48],
    );

    // EncryptedExtensions

    let mut ee_extensions = Vec::new();

    if extended {
        ee_extensions.push(ServerHelloExtension::new_extended_main_secret());
    }

    {
        let ee = Handshake::EncryptedExtensions(EncryptedExtensions::new(&ee_extensions)?);
        let record = TlsPlaintext::new_handshake(ee)?;
        let nonce = xor(context.pad_nonce(), server_write_iv);
        let encrypted = TlsCiphertext::encrypt(&record, server_write_key, nonce)?;
        let ee_raw = encrypted.to_raw();
        conn.write_all(&ee_raw)?;
    }

    // CertificateRequest

    // {
    //     let c_r = Handshake::CertificateRequest(CertificateRequest::new(&[
    //         CertificateRequestExtension::new_signature_algorithms(&[
    //             SignatureScheme::rsa_pkcs1_sha256,
    //         ])?,
    //     ])?);
    //     let record = TlsPlaintext::new_handshake(c_r)?;
    //     let encrypted = TlsCiphertext::encrypt(
    //         &record,
    //         server_write_key,
    //         context.pad_nonce(),
    //     )?;
    //     conn.write_all(&encrypted.to_raw())?;
    // }

    // Certificate

    // {
    //     let cert = Handshake::Certificate(Certificate {});
    //     let record = TlsPlaintext::new_handshake(cert)?;
    //     let encrypted = TlsCiphertext::encrypt(
    //         &record,
    //         (*server_handshake_traffic_secret).try_into()?,
    //         context.pad_nonce(),
    //     )?;
    //     conn.write_all(&encrypted.to_raw())?;
    // }

    Ok(())
}

fn handle_connection(mut conn: TcpStream) -> Result<()> {
    if let Err(e) = handshake(&mut conn) {
        match e.downcast::<TlsAlert>() {
            Ok(alert) => {
                tracing::warn!("Alert: {alert:?}");
            }
            Err(e) => return Err(e),
        }
    }

    let mut buf = [0; 2800];
    loop {
        let n = conn.read(&mut buf)?;

        if n == 0 {
            continue;
        }

        tracing::info!("Read {n} bytes");
        let record = TlsPlaintext::from_raw(&buf[..n])?;

        tracing::info!(?record);
    }

    // Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("trace").init();

    let listener = TcpListener::bind("0.0.0.0:3001")?;

    for conn in listener.incoming().filter_map(Result::ok) {
        _ = handle_connection(conn)
            .inspect_err(|e| tracing::error!("TLS connection handle error: {e:?}"));
    }

    Ok(())
}
