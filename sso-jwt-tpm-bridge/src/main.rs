#[allow(clippy::print_stderr)]
fn main() {
    enclaveapp_core::process::harden_process();

    let mut server = enclaveapp_tpm_bridge::BridgeServer::new("sso-jwt", "cache-key");
    if let Err(e) = server.run_stdio() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
