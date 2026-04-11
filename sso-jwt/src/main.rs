use clap::Parser;

mod cli;
mod exec;
mod shell_init;
#[cfg(target_os = "windows")]
mod wsl_install;

#[allow(clippy::print_stderr, clippy::exit)]
fn main() {
    let cli = cli::Cli::parse();
    if let Err(e) = cli::run(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
