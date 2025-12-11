use anyhow::{Result, anyhow, bail};
use crypt::{hash::sha::Sha1, x25519};
use tls::{
    cipher_suite::TLS_AES_256_GCM_SHA384,
    hkdf::{derive_secret, hkdf_extract},
    record::{
        TlsCiphertext, TlsContent, TlsPlaintext,
        handshake::{
            Handshake,
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

const RANDOM: &[u8; 32] = &[
    0xEB, 0x88, 0x89, 0xA0, 0x21, 0xE6, 0x78, 0x7B, 0x19, 0xA5, 0xB1, 0xF3, 0x3C, 0x6D, 0xD6, 0xE8,
    0xD7, 0xFA, 0x0A, 0xAC, 0x3D, 0xB4, 0x51, 0xE5, 0x50, 0x29, 0x18, 0xEA, 0x80, 0x33, 0xEB, 0x91,
];

struct TlsContext {
    seq_nonce: AtomicU64,
}

impl TlsContext {
    pub fn new() -> Self {
        Self {
            seq_nonce: AtomicU64::new(0),
        }
    }

    pub fn nonce(&self) -> u64 {
        self.seq_nonce.fetch_add(1, Ordering::Relaxed)
    }
}

fn handshake(conn: &mut TcpStream) -> Result<()> {
    const VERSION: u16 = 0x0304;

    let mut buf = [0; 2800];
    let n = conn.read(&mut buf)?;

    // ClientHello

    let client_hello_raw = &buf[..n];
    let client_hello_record = TlsPlaintext::from_raw(client_hello_raw)?;
    let TlsContent::Handshake(Handshake::ClientHello(hello)) = client_hello_record.fragment else {
        bail!("Not client hello");
    };
    let exts = OrganizedClientExtensions::organize(hello.extensions);
    let key_share = exts
        .key_share
        .ok_or(anyhow!("Missing key_share"))?
        .to_hashmap();

    let x25519_peer_pub = key_share
        .get(&NamedGroup::x25519)
        .ok_or(anyhow!("No x25519 key share"))?;
    let (x25519_pub, x25519_priv) = x25519::get_keypair();
    let key_ecdhe = x25519::get_shared_key(x25519_priv, x25519_peer_pub.as_ref().try_into()?);

    let key_psk = [48; 0];

    // ServerHello

    let server_hello = Handshake::ServerHello(ServerHello::new(
        RANDOM,
        &hello.legacy_session_id,
        TLS_AES_256_GCM_SHA384,
        &[
            ServerHelloExtension::new_supported_versions(VERSION),
            ServerHelloExtension::new_key_share(KeyShareEntry::new(
                NamedGroup::x25519,
                &x25519_pub,
            ))?,
            ServerHelloExtension::new_extended_main_secret(),
            ServerHelloExtension::new_pre_shared_key(0),
        ],
    ));
    let server_hello_record = TlsPlaintext::new_handshake(server_hello)?;
    let server_hello_raw = server_hello_record.to_raw();
    conn.write_all(&server_hello_raw)?;

    let context = TlsContext::new();

    let early_secret = hkdf_extract::<Sha1>(&[48; 0], &key_psk);

    let handshake_secret = hkdf_extract::<Sha1>(
        &derive_secret::<Sha1>(&early_secret, "derived", &[]),
        &key_ecdhe,
    );
    let transcript = {
        let mut x = Vec::new();
        x.extend(client_hello_raw);
        x.extend(server_hello_raw);
        x.into_boxed_slice()
    };
    let server_handshake_traffic_secret =
        derive_secret::<Sha1>(&handshake_secret, "s hs traffic", &transcript);
    dbg!(&server_handshake_traffic_secret);

    let main_secret = hkdf_extract::<Sha1>(
        &derive_secret::<Sha1>(&handshake_secret, "derived", &[]),
        &[0; 48],
    );

    // EncryptedExtensions

    {
        let e_e = Handshake::EncryptedExtensions(EncryptedExtensions::new());
        let record = TlsPlaintext::new_handshake(e_e)?;
        let nonce = {
            let mut x = [0; 12];
            x[..8].copy_from_slice(&context.nonce().to_be_bytes());
            x
        };
        let encrypted = TlsCiphertext::encrypt(
            &record,
            (*server_handshake_traffic_secret).try_into()?,
            nonce,
        )?;
        conn.write_all(&encrypted.to_raw())?;
    }

    // CertificateRequest

    {
        let c_r = Handshake::CertificateRequest(CertificateRequest::new(&[
            CertificateRequestExtension::new_signature_algorithms(&[
                SignatureScheme::rsa_pkcs1_sha256,
            ])?,
        ])?);
        let record = TlsPlaintext::new_handshake(c_r)?;
        let nonce = {
            let mut x = [0; 12];
            x[..8].copy_from_slice(&context.nonce().to_be_bytes());
            x
        };
        let encrypted = TlsCiphertext::encrypt(
            &record,
            (*server_handshake_traffic_secret).try_into()?,
            nonce,
        )?;
        conn.write_all(&encrypted.to_raw())?;
    }

    Ok(())
}

fn handle_connection(mut conn: TcpStream) -> Result<()> {
    handshake(&mut conn)?;

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
