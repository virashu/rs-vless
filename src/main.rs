use anyhow::{Result, anyhow, bail};
use crypt::x25519;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};
use tls::{
    cipher_suite::TLS_AES_256_GCM_SHA348,
    record::{
        TlsContent, TlsPlaintext,
        handshake::{
            Handshake,
            certificate_request::{CertificateRequest, CertificateRequestExtension},
            extension::{KeyShareEntry, NamedGroup, SignatureScheme},
            server_hello::{ServerHello, ServerHelloExtension},
        },
    },
};

use crate::organized_extensions::OrganizedClientExtensions;

mod organized_extensions;

const RANDOM: &[u8; 32] = &[
    0xEB, 0x88, 0x89, 0xA0, 0x21, 0xE6, 0x78, 0x7B, 0x19, 0xA5, 0xB1, 0xF3, 0x3C, 0x6D, 0xD6, 0xE8,
    0xD7, 0xFA, 0x0A, 0xAC, 0x3D, 0xB4, 0x51, 0xE5, 0x50, 0x29, 0x18, 0xEA, 0x80, 0x33, 0xEB, 0x91,
];

fn handshake(conn: &mut TcpStream) -> Result<()> {
    const VERSION: u16 = 0x0304;

    let mut buf = [0; 2800];
    let n = conn.read(&mut buf)?;

    // ClientHello

    let record = TlsPlaintext::from_raw(&buf[..n])?;
    let TlsContent::Handshake(Handshake::ClientHello(hello)) = record.record else {
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
    let x25519_shared = x25519::get_shared_key(x25519_priv, x25519_peer_pub.as_ref().try_into()?);

    // ServerHello

    let s_h = Handshake::ServerHello(ServerHello::new(
        RANDOM,
        &hello.legacy_session_id,
        TLS_AES_256_GCM_SHA348,
        &[
            ServerHelloExtension::new_supported_versions(VERSION),
            ServerHelloExtension::new_key_share(KeyShareEntry::new(
                NamedGroup::x25519,
                &x25519_pub,
            ))?,
        ],
    ));
    let record = TlsPlaintext::new_handshake(s_h)?;
    conn.write_all(&record.to_raw())?;

    // CertificateRequest

    let c_r = Handshake::CertificateRequest(CertificateRequest::new(&[
        CertificateRequestExtension::new_signature_algorithms(&[SignatureScheme::rsa_pkcs1_sha256]),
    ]));
    let record = TlsPlaintext::new_handshake(c_r)?;
    conn.write_all(&record.to_raw())?;

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
        _ = handle_connection(conn).inspect_err(|e| tracing::error!("{e}"));
    }

    Ok(())
}
