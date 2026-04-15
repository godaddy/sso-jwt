#[allow(clippy::print_stderr)]
fn main() {
    let mut server = enclaveapp_tpm_bridge::BridgeServer::new("sso-jwt", "cache-key");
    if let Err(e) = server.run_stdio() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
