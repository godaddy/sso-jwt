use clap::Parser;

mod cache;
mod cli;
mod config;
mod exec;
mod jwt;
mod oauth;
mod secure_storage;
mod shell_init;

#[allow(clippy::print_stderr, clippy::exit)]
fn main() {
    let cli = cli::Cli::parse();
    if let Err(e) = cli::run(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
