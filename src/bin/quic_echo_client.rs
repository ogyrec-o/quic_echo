/*
QUIC Echo Client (quinn + rustls)
=================================

This binary connects to the QUIC echo server and tests either:
  - a DATAGRAM ping (if --datagram is set), or
  - a BIDIRECTIONAL STREAM ping (default).

ALPN
----
The client advertises the same custom ALPN as the server:
    "freven-quic-test"
Both sides must match to negotiate the protocol.

Certificate verification (IMPORTANT)
------------------------------------
This client uses a custom verifier that *skips* server certificate validation
(SkipServerVerification). That means:
  - It will connect even if the server uses a self-signed cert.
  - It is NOT secure against man-in-the-middle attacks.
Use this ONLY for local/dev testing. In production:
  - remove the "dangerous" verifier,
  - trust a real CA, or pin a known certificate.

Networking debug info
---------------------
Before connecting, the client runs:
  ip route get <remote-ip>
to print the chosen source IP and interface. This is optional but useful when
debugging multi-homed hosts / VPNs / IPv4 vs IPv6 routing.

How the client works (high level)
---------------------------------
- Resolves host:port to a SocketAddr.
- Creates a client Endpoint bound to 0.0.0.0:0 (ephemeral UDP port).
- Applies TransportConfig datagram buffer tuning.
- Connects to the server with SNI = host.
- Prints negotiated ALPN.
- Sends "ping" and waits up to 5 seconds for the echoed response:
  - datagram mode: send_datagram + read_datagram
  - stream mode: open_bi + write_all + finish + read_to_end
*/

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use quinn::{ClientConfig, Endpoint, TransportConfig};
use regex::Regex;
use std::{net::SocketAddr, process::Command, sync::Arc, time::Duration};

use quinn::crypto::rustls::{NoInitialCipherSuite, QuicClientConfig};
use rustls::{
  client::danger,
  crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
  pki_types::{CertificateDer, ServerName, UnixTime},
  DigitallySignedStruct, SignatureScheme,
};

const ALPN: &[u8] = b"freven-quic-test";

#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);
impl SkipServerVerification {
  fn new() -> Arc<Self> {
    Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
  }
}
impl danger::ServerCertVerifier for SkipServerVerification {
  fn verify_server_cert(
    &self,
    _end_entity: &CertificateDer<'_>,
    _intermediates: &[CertificateDer<'_>],
    _server_name: &ServerName<'_>,
    _ocsp: &[u8],
    _now: UnixTime,
  ) -> std::result::Result<danger::ServerCertVerified, rustls::Error> {
    Ok(danger::ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> std::result::Result<danger::HandshakeSignatureValid, rustls::Error> {
    verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> std::result::Result<danger::HandshakeSignatureValid, rustls::Error> {
    verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    self.0.signature_verification_algorithms.supported_schemes()
  }
}

fn make_client_config() -> Result<ClientConfig, NoInitialCipherSuite> {
  let mut tls = rustls::ClientConfig::builder()
    .dangerous()
    .with_custom_certificate_verifier(SkipServerVerification::new())
    .with_no_client_auth();

  tls.alpn_protocols = vec![ALPN.to_vec()];

  Ok(ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?)))
}

fn route_get(remote_ip: &str) -> (Option<String>, Option<String>) {
  let mut cmd = Command::new("ip");
  cmd.arg("-o");
  if remote_ip.contains(':') {
    cmd.args(["-6", "route", "get", remote_ip]);
  } else {
    cmd.args(["-4", "route", "get", remote_ip]);
  }

  let out = match cmd.output() {
    Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
    Err(_) => return (None, None),
  };

  let re_dev = Regex::new(r"\bdev\s+(\S+)").unwrap();
  let re_src = Regex::new(r"\bsrc\s+(\S+)").unwrap();
  let re_from = Regex::new(r"\bfrom\s+(\S+)").unwrap();

  let dev = re_dev
    .captures(&out)
    .and_then(|c| c.get(1))
    .map(|m| m.as_str().to_string());

  let mut src = re_src
    .captures(&out)
    .and_then(|c| c.get(1))
    .map(|m| m.as_str().to_string());

  if src.is_none() {
    src = re_from
      .captures(&out)
      .and_then(|c| c.get(1))
      .map(|m| m.as_str().to_string());
  }

  (src, dev)
}

#[derive(Parser, Debug)]
struct Opt {
  #[clap(long)]
  host: String,
  #[clap(long, default_value_t = 12806)]
  port: u16,
  #[clap(long)]
  datagram: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
  let _ = rustls::crypto::ring::default_provider().install_default();

  let opt = Opt::parse();

  let mut addrs = tokio::net::lookup_host((opt.host.as_str(), opt.port))
    .await
    .context("resolve host")?;
  let remote: SocketAddr = addrs.next().context("no resolved addresses")?;
  let remote_ip = remote.ip().to_string();

  let mut endpoint = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;

  let transport = Arc::new({
    let mut t = TransportConfig::default();
    t.datagram_receive_buffer_size(Some(65_536));
    t.datagram_send_buffer_size(2 * 1024 * 1024);
    t
  });

  let mut cfg = make_client_config()?;
  cfg.transport_config(transport);
  endpoint.set_default_client_config(cfg);

  let local_port = endpoint.local_addr()?.port();
  let (src_ip, dev) = route_get(&remote_ip);
  println!(
    "[net] route probe: remote={}:{} local={}:{} iface={}",
    remote_ip,
    remote.port(),
    src_ip.unwrap_or_else(|| "unknown".into()),
    local_port,
    dev.unwrap_or_else(|| "unknown".into())
  );

  let conn = endpoint.connect(remote, opt.host.as_str())?.await?;

  let proto = conn
    .handshake_data()
    .and_then(|x| x.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
    .and_then(|hd| hd.protocol.clone())
    .map(|p| String::from_utf8_lossy(&p).into_owned())
    .unwrap_or_else(|| "<none>".into());
  println!("ALPN: {proto}");

  if opt.datagram {
    conn.send_datagram(Bytes::from_static(b"ping"))?;
    let data = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram()).await??;
    println!("recv(dgram): {:?}", data);
  } else {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"ping").await?;
    send.finish()?;
    let data = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64 * 1024)).await??;
    println!("recv: {:?}", data);
  }

  Ok(())
}
