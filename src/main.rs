fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    eprintln!(
        "Use one of the binaries:\n\
         - quic_echo_server\n\
         - quic_echo_client\n\n\
         Examples:\n\
         cargo run --bin quic_echo_server -- --help\n\
         cargo run --bin quic_echo_client -- --help"
    );
}
