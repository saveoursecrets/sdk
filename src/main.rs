use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use sos::Result;

use sos::commands::{CheckCommand, check};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Sos {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print and monitor audit log events.
    #[clap(
        allow_external_subcommands = true,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        disable_version_flag = true,
        disable_help_flag = true,
        disable_help_subcommand = true
    )]
    Audit {},
    /// Utility tool to check status and integrity.
    Check {
        #[clap(subcommand)]
        cmd: CheckCommand,
    },
    /// Secret storage interactive shell.
    #[clap(
        allow_external_subcommands = true,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        disable_version_flag = true,
        disable_help_flag = true,
        disable_help_subcommand = true
    )]
    Client {},
    /// Secret storage server.
    #[clap(
        allow_external_subcommands = true,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        disable_version_flag = true,
        disable_help_flag = true,
        disable_help_subcommand = true
    )]
    Server {},
}

fn run() -> Result<()> {
    let args = Sos::parse();
    //let args = std::env::args().skip(2).collect::<Vec<_>>();
    let cmd = match args.cmd {
        //Command::Audit {} => "sos-audit",
        Command::Check {cmd} => check::run(cmd)?,
        _ => todo!(),
        //Command::Client {} => "sos-client",
        //Command::Server {} => "sos-server",
    };

    /*
    let argv = Sos::parse();
    let args = std::env::args().skip(2).collect::<Vec<_>>();
    let cmd = match argv.cmd {
        Command::Audit {} => "sos-audit",
        Command::Check {} => "sos-check",
        Command::Client {} => "sos-client",
        Command::Server {} => "sos-server",
    };

    let cmd = if cfg!(debug_assertions) {
        format!("target/debug/{}", cmd)
    } else {
        cmd.to_owned()
    };

    tracing::debug!(cmd = %cmd, args = ?args);

    std::process::Command::new(&cmd).args(args).status()?;

*/
    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    if let Err(e) = run() {
        tracing::error!("{}", e);
    }

    Ok(())
}
