# QUIC Echo (Rust / quinn + rustls)

A minimal QUIC echo server/client written in Rust using **quinn** + **rustls**.

It’s meant as a small, readable example you can copy/paste and adapt.

## Features

- Echo over **bidirectional streams** (reliable)
- Echo over **QUIC datagrams** (unreliable)
- Custom **ALPN**: `freven-quic-test`
- Client prints basic routing info (`ip route get ...`) to show chosen source IP/interface
- Tuned QUIC datagram buffers (recv: 64 KiB, send: 2 MiB)

## Binaries

- `quic_echo_server` - listens on UDP and echoes streams + datagrams
- `quic_echo_client` - connects and sends `ping` via stream (default) or datagram (`--datagram`)

## Requirements

- Rust (stable)
- OpenSSL (only for generating a self-signed cert for local testing)
- Linux recommended for the `ip route get` debug output (client still works without it)

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

Server defaults:
- `--host 0.0.0.0`
- `--port 12806`
- `--cert cert.pem`
- `--key key.pem`

If `cert.pem`/`key.pem` are in the repo root, you can run:

```bash
cargo run --bin quic_echo_server
```

Or explicitly:

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

## ALPN

Both client and server must use the same ALPN (`freven-quic-test`), otherwise the QUIC handshake will fail.

## How it works (high level)

Server:
- Creates a QUIC endpoint bound to `host:port` (UDP).
- Accepts incoming connections in a loop.
- For each connection:
  - prints negotiated ALPN and remote address,
  - spawns a datagram echo task (`read_datagram` -> `send_datagram`),
  - accepts bidirectional streams and echoes back all bytes until EOF.

Client:
- Resolves `host:port` to a `SocketAddr`.
- Creates a client endpoint bound to `0.0.0.0:0` (ephemeral UDP port).
- Applies TransportConfig datagram buffer tuning.
- Connects to the server and prints negotiated ALPN.
- Sends `ping` and waits up to 5 seconds for the echoed response:
  - stream: `open_bi` + `write_all` + `finish` + `read_to_end`
  - datagram: `send_datagram` + `read_datagram`

## Security note

The client uses a "dangerous" certificate verifier that **skips server certificate validation**
to allow self-signed certs during local testing.

Do **not** use this approach in production:
- remove the custom verifier,
- trust a real CA, or pin a known certificate.

## License

MIT - see `LICENSE`.
