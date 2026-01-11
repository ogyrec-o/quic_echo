# QUIC Echo (Rust / quinn + rustls)

A minimal QUIC echo server/client written in Rust using **quinn** + **rustls**.

Features:
- Echo over **bidirectional streams** (reliable)
- Echo over **QUIC datagrams** (unreliable)
- Custom **ALPN**: `freven-quic-test`
- Simple routing debug on client (`ip route get ...`) to show chosen source IP/interface

## Binaries

- `quic_echo_server` - listens on UDP and echoes streams + datagrams
- `quic_echo_client` - connects and sends `ping` via stream (default) or datagram (`--datagram`)

## Requirements

- Rust (stable)
- OpenSSL (only for generating a self-signed cert for local testing)

## Generate a self-signed certificate (dev)

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=localhost"
```

Notes:
- Self-signed cert is fine for local testing.
- For production, use a real CA-issued certificate and enable proper verification on the client.

## Run server

```bash
cargo run --bin quic_echo_server -- \
  --host 0.0.0.0 --port 12806 \
  --cert cert.pem --key key.pem
```

## Run client (stream mode, default)

```bash
cargo run --bin quic_echo_client -- \
  --host localhost --port 12806
```

## Run client (datagram mode)

```bash
cargo run --bin quic_echo_client -- \
  --host localhost --port 12806 --datagram
```

## How it works (high level)

Server:
- Accepts incoming QUIC connections (TLS via rustls).
- Spawns a task to echo received **datagrams** back to the sender.
- Accepts incoming **bidirectional streams** and echoes back bytes until EOF.

Client:
- Resolves host/port, prints route info (`ip route get`) for debugging.
- Connects using the same ALPN (`freven-quic-test`).
- Sends `ping` via stream or datagram and prints the echoed response.

## Security note

The client uses a "dangerous" certificate verifier that **skips server certificate validation** to allow self-signed certs during local testing.  
Do **not** use this approach in production.
