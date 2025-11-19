use anyhow::{Result, bail};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};
use tls::{
    CipherSuite,
    handshake::{
        Handshake,
        extension::{ClientHelloExtensionContent, ServerHelloExtension, ServerName},
        server_hello::ServerHello,
    },
    record::{TlsContent, TlsPlaintext},
};

fn handle_connection(mut conn: TcpStream) -> Result<()> {
    let mut buf = [0; 2800];
    let n = conn.read(&mut buf)?;

    tracing::info!("Read {n} bytes");

    let record = TlsPlaintext::from_raw(&buf[..n])?;

    let TlsContent::Handshake(Handshake::ClientHello(hello)) = record.record else {
        bail!("Not client hello");
    };

    // let key_share = hello
    //     .extensions
    //     .iter()
    //     .find_map(|x| match &x.content {
    //         ClientHelloExtensionContent::KeyShare(e) => Some(e),
    //         _ => None,
    //     })
    //     .unwrap();

    // let signature_algorithms = hello
    //     .extensions
    //     .iter()
    //     .find_map(|x| match &x.content {
    //         ClientHelloExtensionContent::SignatureAlgorithms(e) => Some(e),
    //         _ => None,
    //     })
    //     .unwrap();

    // let psk_key_exchange_modes = hello
    //     .extensions
    //     .iter()
    //     .find_map(|x| match &x.content {
    //         ClientHelloExtensionContent::PskKeyExchangeModes(e) => Some(e),
    //         _ => None,
    //     })
    //     .unwrap();

    // let pre_shared_key = hello
    //     .extensions
    //     .iter()
    //     .find_map(|x| match &x.content {
    //         ClientHelloExtensionContent::PreSharedKey(e) => Some(e),
    //         _ => None,
    //     })
    //     .unwrap();

    let server_name = hello
        .extensions
        .iter()
        .find_map(|x| match &x.content {
            ClientHelloExtensionContent::ServerName(e) => Some(e),
            _ => None,
        })
        .unwrap();

    let ServerName::HostName(name) = &server_name.server_name_list[0];
    let name = String::from_utf8_lossy(name.as_ref());
    tracing::info!(?name);

    let handshake = Handshake::ServerHello(ServerHello::new(
        &[0; 32],
        &hello.legacy_session_id,
        CipherSuite {
            aead_algorithm: 192,
            hkdf_hash: 48,
        },
        &[ServerHelloExtension::new_supported_versions(772)],
    ));

    let record = TlsPlaintext::new_handshake(handshake)?;

    conn.write_all(&record.to_raw())?;

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
