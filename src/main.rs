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

const RANDOM: &[u8; 32] = &[
    0xEB, 0x88, 0x89, 0xA0, 0x21, 0xE6, 0x78, 0x7B, 0x19, 0xA5, 0xB1, 0xF3, 0x3C, 0x6D, 0xD6, 0xE8,
    0xD7, 0xFA, 0x0A, 0xAC, 0x3D, 0xB4, 0x51, 0xE5, 0x50, 0x29, 0x18, 0xEA, 0x80, 0x33, 0xEB, 0x91,
];

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
        ServerHelloExtension::new_key_share(KeyShareEntry::new(NamedGroup::x25519, RANDOM))?;

    let s_h = Handshake::ServerHello(ServerHello::new(
        RANDOM,
        &hello.legacy_session_id,
        CipherSuite {
            aead_algorithm: 0x13,
            hkdf_hash: 0x02,
        },
        &[ServerHelloExtension::new_supported_versions(772), key_share],
    ));

    let record = TlsPlaintext::new_handshake(s_h)?;

    // println!(
    //     "{}",
    //     record
    //         .to_raw()
    //         .iter()
    //         .map(|x| format!("0x{x:02X?} "))
    //         .collect::<String>()
    // );

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
