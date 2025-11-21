use anyhow::{Result, anyhow, bail};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};
use tls::{
    CipherSuite,
    record::{
        TlsContent, TlsPlaintext,
        handshake::{
            Handshake,
            extension::{KeyShareEntry, NamedGroup, ServerHelloExtension},
            server_hello::ServerHello,
        },
    },
};

use crate::organized_extensions::OrganizedClientExtensions;

mod organized_extensions;

fn handshake(conn: &mut TcpStream) -> Result<()> {
    let mut buf = [0; 2800];
    let n = conn.read(&mut buf)?;

    tracing::info!("Read {n} bytes");

    let record = TlsPlaintext::from_raw(&buf[..n])?;

    let TlsContent::Handshake(Handshake::ClientHello(hello)) = record.record else {
        bail!("Not client hello");
    };

    let exts = OrganizedClientExtensions::organize(hello.extensions);

    let key_share = exts.key_share.ok_or(anyhow!("Missing key_share"))?;
    tracing::info!("{key_share:#?}");

    // let server_name = exts.server_name.unwrap();
    // let ServerName::HostName(name) = &server_name.server_name_list[0];
    // let name = String::from_utf8_lossy(name.as_ref());
    // tracing::info!(?name);

    let key_share =
        ServerHelloExtension::new_key_share(KeyShareEntry::new(NamedGroup::x25519, &[0; 32]))?;

    let s_h = Handshake::ServerHello(ServerHello::new(
        &[0; 32],
        &hello.legacy_session_id,
        CipherSuite {
            aead_algorithm: 192,
            hkdf_hash: 48,
        },
        &[ServerHelloExtension::new_supported_versions(772), key_share],
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
