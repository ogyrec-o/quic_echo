/*
QUIC Echo Server (quinn + rustls)
=================================

This binary starts a QUIC server that echoes back:
  1) DATAGRAMS (unreliable messages), and
  2) BIDIRECTIONAL STREAM data (reliable byte streams).

It uses TLS certificates (via rustls) and advertises a custom ALPN:
    "freven-quic-test"
The client must use the same ALPN, otherwise the handshake will fail.

Generate a self-signed certificate (dev/testing)
------------------------------------------------
Run this in the project directory (or wherever you want cert.pem/key.pem):

  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout key.pem -out cert.pem -days 365 \
    -subj "/CN=localhost"

Notes:
- This cert is self-signed → browsers/clients won't trust it by default.
- For local testing it’s fine. For production you should use a real CA-issued cert.
- CN/SAN should match the hostname you connect to (e.g. localhost, your domain, etc).
  (Modern TLS expects SAN, but for quick local tests this usually works.)

How the server works (high level)
---------------------------------
- Creates a QUIC endpoint bound to host:port (UDP).
- Accepts incoming connections in a loop.
- For each connection:
  - prints the negotiated ALPN and remote address,
  - spawns a task that reads incoming datagrams and echoes them back,
  - accepts bidirectional streams in a loop; each stream is echoed back in a spawned task.

Datagram buffer tuning
----------------------
TransportConfig is tweaked to increase send/receive buffers for datagrams:
  - receive buffer: 64 KiB
  - send buffer:    2 MiB
This helps avoid drops when sending bigger bursts of datagrams.
*/

use anyhow::{Context, Result};
use clap::Parser;
use quinn::{Endpoint, Incoming, TransportConfig};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::pki_types::pem::PemObject;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

const ALPN: &[u8] = b"freven-quic-test";

#[derive(Parser, Debug)]
struct Opt {
  #[clap(long, default_value = "0.0.0.0")]
  host: String,
  #[clap(long, default_value_t = 12806)]
  port: u16,
  #[clap(long, default_value = "cert.pem")]
  cert: PathBuf,
  #[clap(long, default_value = "key.pem")]
  key: PathBuf,
}

fn read_certs(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>> {
  let it = CertificateDer::pem_file_iter(path)
    .with_context(|| format!("read PEM cert {:?}", path))?;
  let certs = it
    .collect::<std::result::Result<Vec<_>, _>>()
    .with_context(|| format!("parse PEM cert {:?}", path))?;
  Ok(certs)
}

fn read_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>> {
  PrivateKeyDer::from_pem_file(path)
    .with_context(|| format!("read PEM key {:?}", path))
}

fn make_server_config(cert: PathBuf, key: PathBuf) -> Result<quinn::ServerConfig> {
  let certs = read_certs(&cert)?;
  let key = read_key(&key)?;

  let mut tls = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("with_single_cert")?;
  tls.alpn_protocols = vec![ALPN.to_vec()];

  let mut server_config =
    quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));

  // datagrams tuning
  let transport: &mut TransportConfig = Arc::get_mut(&mut server_config.transport).unwrap();
  transport.datagram_receive_buffer_size(Some(65_536));
  transport.datagram_send_buffer_size(2 * 1024 * 1024);

  Ok(server_config)
}

#[tokio::main]
async fn main() -> Result<()> {
  let _ = rustls::crypto::ring::default_provider().install_default();

  let opt = Opt::parse();
  let addr: SocketAddr = format!("{}:{}", opt.host, opt.port).parse()?;

  let server_config = make_server_config(opt.cert, opt.key)?;
  let endpoint = Endpoint::server(server_config, addr)?;
  println!("QUIC echo server listening on {} (UDP)", endpoint.local_addr()?);

  while let Some(incoming) = endpoint.accept().await {
    tokio::spawn(async move {
      if let Err(e) = handle_incoming(incoming).await {
        eprintln!("connection failed: {e}");
      }
    });
  }
  Ok(())
}

async fn handle_incoming(incoming: Incoming) -> Result<()> {
  let conn = incoming.await?;

  let proto = conn
    .handshake_data()
    .and_then(|x| x.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
    .and_then(|hd| hd.protocol.clone())
    .map(|p| String::from_utf8_lossy(&p).into_owned())
    .unwrap_or_else(|| "<none>".into());
  println!("ALPN: {proto} from {}", conn.remote_address());

  // datagram echo loop
  let dgram_conn = conn.clone();
  tokio::spawn(async move {
    while let Ok(data) = dgram_conn.read_datagram().await {
      if let Err(e) = dgram_conn.send_datagram(data) {
        eprintln!("datagram send failed: {e}");
      }
    }
  });

  // stream echo loop
  loop {
    let (mut send, mut recv) = match conn.accept_bi().await {
      Ok(s) => s,
      Err(quinn::ConnectionError::ApplicationClosed { .. }) => return Ok(()),
      Err(e) => return Err(e.into()),
    };

    tokio::spawn(async move {
      let mut buf = [0u8; 16 * 1024];
      loop {
        match tokio::io::AsyncReadExt::read(&mut recv, &mut buf).await {
          Ok(0) => {
            let _ = send.finish();
            break;
          }
          Ok(n) => {
            if tokio::io::AsyncWriteExt::write_all(&mut send, &buf[..n])
              .await
              .is_err()
            {
              break;
            }
          }
          Err(_) => break,
        }
      }
    });
  }
}
