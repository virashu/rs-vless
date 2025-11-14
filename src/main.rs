use anyhow::bail;
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
};
use tls::{
    CipherSuite,
    handshake::{Handshake, server_hello::ServerHello},
};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let listener = TcpListener::bind("0.0.0.0:3001")?;

    for mut conn in listener.incoming().filter_map(Result::ok) {
        let mut buf = [0; 1000];
        let n = conn.read(&mut buf)?;

        println!("Read {n} bytes");
        // println!("{:02X?}", &buf[5..n]);

        let Handshake::ClientHello(hello) = Handshake::from_raw(&buf[5..n])? else {
            bail!("Not client hello");
        };

        println!("Extensions = {:#?}", hello.extensions);

        let handshake = Handshake::ServerHello(ServerHello::new(
            &[0; 32],
            &hello.legacy_session_id,
            CipherSuite {
                aead_algorithm: 192,
                hkdf_hash: 48,
            },
            &[],
        ));

        conn.write_all(&handshake.to_raw())?;
    }

    Ok(())
}
