use anyhow::{Result, anyhow, bail};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};
use tls::{
    CipherSuite,
    record::handshake::{
        Handshake,
        extension::{ClientHelloExtensionContent, ServerHelloExtension},
        server_hello::ServerHello,
    },
    record::{TlsContent, TlsPlaintext},
};

fn handshake(conn: &mut TcpStream) -> Result<()> {
    let mut buf = [0; 2800];
    let n = conn.read(&mut buf)?;

    tracing::info!("Read {n} bytes");

    let record = TlsPlaintext::from_raw(&buf[..n])?;

    let TlsContent::Handshake(Handshake::ClientHello(hello)) = record.record else {
        bail!("Not client hello");
    };

    let mut key_share = None;
    let mut signature_algorithms = None;
    let mut psk_key_exchange_modes = None;
    let mut pre_shared_key = None;

    for ext in hello.extensions {
        match ext.content {
            ClientHelloExtensionContent::KeyShare(e) => key_share = Some(e),
            ClientHelloExtensionContent::SignatureAlgorithms(e) => signature_algorithms = Some(e),
            ClientHelloExtensionContent::PskKeyExchangeModes(e) => psk_key_exchange_modes = Some(e),
            ClientHelloExtensionContent::PreSharedKey(e) => pre_shared_key = Some(e),
            _ => {}
        }
    }

    let key_share = key_share.ok_or(anyhow!("Missing key_share"))?;
    tracing::info!("{key_share:#?}");

    // let server_name = hello
    //     .extensions
    //     .iter()
    //     .find_map(|x| match &x.content {
    //         ClientHelloExtensionContent::ServerName(e) => Some(e),
    //         _ => None,
    //     })
    //     .unwrap();
    // let ServerName::HostName(name) = &server_name.server_name_list[0];
    // let name = String::from_utf8_lossy(name.as_ref());
    // tracing::info!(?name);

    let s_h = Handshake::ServerHello(ServerHello::new(
        &[0; 32],
        &hello.legacy_session_id,
        CipherSuite {
            aead_algorithm: 192,
            hkdf_hash: 48,
        },
        &[ServerHelloExtension::new_supported_versions(771)],
    ));

    let record = TlsPlaintext::new_handshake(s_h)?;
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
