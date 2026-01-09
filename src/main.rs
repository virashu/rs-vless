use anyhow::{Result, anyhow, bail};
use asn1::{
    DataElement, X509CertificateV3,
    object_identifiers::{rsassaPss, sha256WithRSAEncryption},
    parse_der,
};
use crypt::{
    elliptic::x25519,
    hash::{
        Hasher,
        sha::{Sha256, Sha384},
    },
    hmac::hmac_hash,
    rsa::{PrivateKey, PublicKey},
};
use tls::{
    cipher_suite::TLS_AES_256_GCM_SHA384,
    error::TlsAlert,
    hkdf::{derive_secret, hkdf_expand_label, hkdf_extract},
    record::{
        TlsCiphertext, TlsContent, TlsPlaintext,
        handshake::{
            Handshake,
            certificate::{Certificate, CertificateEntry},
            certificate_verify::CertificateVerify,
            encrypted_extensions::EncryptedExtensions,
            extension::{KeyShareEntry, NamedGroup, SignatureScheme},
            finished::Finished,
            server_hello::{ServerHello, ServerHelloExtension},
        },
    },
};
use utils::concat_dyn;

use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::organized_extensions::OrganizedClientExtensions;

mod organized_extensions;

const VERSION: u16 = 0x0304;

fn load_cert() -> X509CertificateV3 {
    let certificate = fs::read("cert.cer").unwrap();
    let data = parse_der(&certificate);
    X509CertificateV3::from_data_element(&data)
}

fn load_rsa_keys() -> (PrivateKey, PublicKey) {
    let encoded = std::fs::read("key.der").unwrap();

    if let DataElement::Sequence(seq) = parse_der(&encoded)
        && let DataElement::OctetString(octets) = &seq[2]
        && let DataElement::Sequence(numbers) = parse_der(octets)
        && let DataElement::Integer(modulus) = &numbers[1]
        && let DataElement::Integer(public_exponent) = &numbers[2]
        && let DataElement::Integer(private_exponent) = &numbers[3]
    {
        (
            PrivateKey {
                modulus: modulus.0.clone(),
                exponent: private_exponent.0.clone(),
            },
            PublicKey {
                modulus: modulus.0.clone(),
                exponent: public_exponent.0.clone(),
            },
        )
    } else {
        panic!()
    }
}

fn xor<const N: usize>(mut a: [u8; N], b: [u8; N]) -> [u8; N] {
    for i in 0..N {
        a[i] ^= b[i];
    }
    a
}

struct ClientHelloInfo {
    legacy_session_id: Box<[u8]>,

    supported_versions: Box<[u16]>,
    // server_name: Option<String>,

    // Cryptography
    key_share: HashMap<NamedGroup, Box<[u8]>>,
    // signature_algorithms: Box<[SignatureScheme]>,
    server_share: Option<KeyShareEntry>,
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
        x[(L - 8)..L].copy_from_slice(&self.nonce().to_be_bytes());
        x
    }
}

fn server_hello(client_info: ClientHelloInfo) -> Result<Box<[u8]>> {
    let mut sh_extensions = Vec::from([ServerHelloExtension::new_supported_versions(VERSION)]);

    if let Some(share) = client_info.server_share {
        sh_extensions.push(ServerHelloExtension::new_key_share(share)?);
    }

    // if flag_psk {
    //     sh_extensions.push(ServerHelloExtension::new_pre_shared_key(0));
    // }

    let server_hello = Handshake::ServerHello(ServerHello::new(
        &rand::random(),
        &client_info.legacy_session_id,
        TLS_AES_256_GCM_SHA384,
        &sh_extensions,
    ));
    let sh_record = TlsPlaintext::new_handshake(server_hello)?;
    Ok(sh_record.to_raw())
}

fn handshake(conn: &mut TcpStream) -> Result<()> {
    let mut buf = [0; 2800];
    let n = conn.read(&mut buf)?;

    let mut transcript = Vec::<u8>::new();

    // ClientHello

    let ch_raw = &buf[..n];
    transcript.extend(&ch_raw[5..]);
    let ch_record = TlsPlaintext::from_raw(ch_raw)?;
    let TlsContent::Handshake(Handshake::ClientHello(client_hello)) = ch_record.fragment else {
        bail!("Not client hello");
    };
    let ch_exts = OrganizedClientExtensions::organize(client_hello.extensions);

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

    // ServerHello

    let server_share = x25519_public.map(|share| KeyShareEntry::new(NamedGroup::x25519, &share));
    let client_info = ClientHelloInfo {
        legacy_session_id: client_hello.legacy_session_id,
        supported_versions: ch_exts.supported_versions.unwrap().versions,
        // server_name: ch_exts.server_name,
        key_share,
        server_share,
    };

    let sh_raw = server_hello(client_info)?;
    transcript.extend(&sh_raw[5..]);
    conn.write_all(&sh_raw)?;

    // Key schedule

    let context = TlsContext::new(x25519_shared.map(Box::from), None);

    let early_secret = hkdf_extract::<Sha384>(&[0; 48], context.key_psk());

    let handshake_secret = hkdf_extract::<Sha384>(
        &derive_secret::<Sha384>(&early_secret, "derived", &[]),
        context.key_ecdhe(),
    );

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
    {
        let ee = Handshake::EncryptedExtensions(EncryptedExtensions::new(&[])?);
        let record = TlsPlaintext::new_handshake(ee)?;
        transcript.extend(&record.to_raw()[5..]);
        let nonce = xor(context.pad_nonce(), server_write_iv);
        let encrypted = TlsCiphertext::encrypt(&record, server_write_key, nonce)?;
        let ee_raw = encrypted.to_raw();
        conn.write_all(&ee_raw)?;
    }

    // Certificate
    {
        let certificate = fs::read("cert.cer")?;

        let cert = Handshake::Certificate(Certificate::new(
            &[],
            &[CertificateEntry::new(&certificate)?],
        )?);
        let record = TlsPlaintext::new_handshake(cert)?;
        transcript.extend(&record.to_raw()[5..]);
        let nonce = xor(context.pad_nonce(), server_write_iv);
        let encrypted = TlsCiphertext::encrypt(&record, server_write_key, nonce)?;
        conn.write_all(&encrypted.to_raw())?;
    }

    // Determine certificate type
    let cert = load_cert();
    let signature_scheme = if cert.signature_algorithm.is(sha256WithRSAEncryption) {
        tracing::info!("Using RSAE");
        SignatureScheme::rsa_pss_rsae_sha256
    } else if cert.signature_algorithm.is(rsassaPss) {
        tracing::info!("Using RSASSA-PSS");
        SignatureScheme::rsa_pss_pss_sha256
    } else {
        unimplemented!();
    };

    // CertificateVerify
    {
        let transcript_hash = Sha384::hash(&transcript);
        let sign_context = concat_dyn![
            [0x20].repeat(64),
            b"TLS 1.3, server CertificateVerify",
            [0x00],
            transcript_hash,
        ];
        let (private_key, public_key) = load_rsa_keys();
        let signature = crypt::rsa::rsassa_pss_sign::<Sha256, { Sha256::DIGEST_SIZE }>(
            &private_key,
            &sign_context,
        );

        crypt::rsa::rsassa_pss_verify::<Sha256, { Sha256::DIGEST_SIZE }>(
            &public_key,
            &sign_context,
            &signature,
        )
        .unwrap();

        let cv =
            Handshake::CertificateVerify(CertificateVerify::new(signature_scheme, &signature)?);
        let record = TlsPlaintext::new_handshake(cv)?;
        transcript.extend(&record.to_raw()[5..]);
        let nonce = xor(context.pad_nonce(), server_write_iv);
        let encrypted = TlsCiphertext::encrypt(&record, server_write_key, nonce)?;
        conn.write_all(&encrypted.to_raw())?;
    }

    // Finished
    {
        let finished_key =
            hkdf_expand_label::<Sha384>(&server_handshake_traffic_secret, "finished", &[], 48);
        let verify_data = hmac_hash::<Sha384>(&finished_key, &Sha384::hash(&transcript));

        let finished = Handshake::Finished(Finished { verify_data });
        let record = TlsPlaintext::new_handshake(finished)?;
        transcript.extend(&record.to_raw()[5..]);
        let nonce = xor(context.pad_nonce(), server_write_iv);
        let encrypted = TlsCiphertext::encrypt(&record, server_write_key, nonce)?;
        conn.write_all(&encrypted.to_raw())?;
    }

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
