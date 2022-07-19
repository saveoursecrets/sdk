use std::{
    borrow::Cow,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

use sos_client::{
    exec, monitor, signup, Error, Result, StdinPassphraseReader,
};
use sos_readline::read_shell;
use terminal_banner::{Banner, Padding};

use sos_node::{
    cache_dir,
    client::{
        node_cache::NodeCache, run_blocking, ChangesListener, ClientBuilder,
        LocalCache,
    },
};

const WELCOME: &str = include_str!("welcome.txt");

/// Secret storage interactive shell.
#[derive(Parser, Debug)]
#[clap(name = "sos-client", author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create an account.
    Signup {
        /// Server URL.
        #[clap(short, long)]
        server: Url,

        /// Vault name.
        #[clap(short, long)]
        name: Option<String>,

        /// Directory to write the signing keystore.
        #[clap(parse(from_os_str))]
        keystore: PathBuf,
    },
    /// Launch the interactive shell.
    Shell {
        /// Server URL.
        #[clap(short, long)]
        server: Url,

        /// Keystore file containing the signing key.
        #[clap(short, long)]
        keystore: PathBuf,
    },
    /// Monitor server events.
    Monitor {
        /// Server URL.
        #[clap(short, long)]
        server: Url,

        /// Keystore file containing the signing key.
        #[clap(short, long)]
        keystore: PathBuf,
    },
}

/// Ensure a supplied URL is https.
fn ensure_https(url: &Url) -> Result<()> {
    if url.scheme() != "https" {
        Err(Error::ServerHttps(url.clone()))
    } else {
        Ok(())
    }
}

/// Print the welcome information.
fn welcome(server: &Url) -> Result<()> {
    let help_info = r#"Type "help", "--help" or "-h" for command usage
Type "quit" or "q" to exit"#;
    let status_info = format!("Server: {}", server);
    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::from(WELCOME))
        .text(Cow::from(help_info))
        .text(Cow::Owned(status_info))
        .render();
    println!("{}", banner);
    Ok(())
}

fn run() -> Result<()> {
    let args = Cli::parse();

    match args.cmd {
        Command::Monitor { server, keystore } => {
            ensure_https(&server)?;
            monitor(server, keystore)?;
        }
        Command::Signup {
            server,
            keystore,
            name,
        } => {
            ensure_https(&server)?;
            signup(server, keystore, name)?;
        }
        Command::Shell { server, keystore } => {
            ensure_https(&server)?;
            let server_url = server.clone();
            let cache_dir = cache_dir().ok_or_else(|| Error::NoCache)?;
            if !cache_dir.is_dir() {
                return Err(Error::NotDirectory(cache_dir));
            }

            let reader = StdinPassphraseReader {};
            let client = ClientBuilder::new(server, keystore)
                .with_passphrase_reader(Box::new(reader))
                .with_use_agent(true)
                .build()?;
            let listener = ChangesListener::new(client.clone());
            let cache = Arc::new(RwLock::new(NodeCache::new_file_cache(
                client, cache_dir,
            )?));

            welcome(&server_url)?;

            let mut writer = cache.write().unwrap();
            if let Err(e) = run_blocking(writer.load_vaults()) {
                tracing::error!("failed to load vaults: {}", e);
            }
            drop(writer);

            // Hook up to change notifications
            let changes_cache = Arc::clone(&cache);
            listener.spawn(move |notification| {
                //println!("{:#?}", notification);
                let mut writer = changes_cache.write().unwrap();
                if let Err(e) =
                    run_blocking(writer.handle_change(notification))
                {
                    tracing::error!("{}", e);
                }
            });

            let prompt_cache = Arc::clone(&cache);
            let prompt = || -> String {
                let cache = prompt_cache.read().unwrap();
                if let Some(current) = cache.current() {
                    return format!("sos@{}> ", current.name());
                }
                "sos> ".to_string()
            };

            read_shell(
                |line: String| {
                    let shell_cache = Arc::clone(&cache);
                    if let Err(e) = exec(&line, &server_url, shell_cache) {
                        tracing::error!("{}", e);
                    }
                },
                prompt,
            )?;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "sos_client=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    match run() {
        Ok(_) => {}
        Err(e) => {
            tracing::error!("{}", e);
        }
    }
    Ok(())
}
