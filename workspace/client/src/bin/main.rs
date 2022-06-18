use std::{path::PathBuf, fs::File, io::Read};

use clap::{Parser, CommandFactory};
use url::Url;
use web3_keystore::{KeyStore, decrypt};

use sos_client::{Result, Client};
use sos_core::{signer::SingleParty};
use sos_readline::{read_password, read_shell};

/// Secret storage interactive shell.
#[derive(Parser, Debug)]
#[clap(name = "sos-client", author, version, about, long_about = None)]
struct Cli {
    /// Server API URL.
    #[structopt(short, long)]
    api: Url,

    /// Keystore for the signing key.
    #[structopt(short, long)]
    keystore: PathBuf,
}

/// Secret storage shell.
#[derive(Parser, Debug)]
#[clap(name = "sos-shell", author, version, about, long_about = None)]
struct Shell {

}

fn run_shell_command(line: &str) -> Result<()> {
    let it = line.split_ascii_whitespace();
    let mut cmd = Shell::command();
    if line == "quit" || line == "q" {
        std::process::exit(0);
    } else if line == "-V" {
        let version = cmd.render_version();
        print!("{}", version);
    } else if line == "version" || line == "--version" {
        let version = cmd.render_long_version();
        print!("{}", version);
    } else if line == "-h" {
        cmd.print_help()?;
    } else if line == "help" || line == "--help" {
        cmd.print_long_help()?;
    } else {
        match Shell::try_parse_from(it) {
            Ok(args) => {
                println!("Run shell command {:#?}", args);
                //tokio::task::spawn(async move {
                    //run_shell_command(&line).await.unwrap();
                //});
            }
            Err(e) => e.print().expect("unable to write error output"),
        }
    }
    Ok(())
}

/// Print the welcome information.
fn welcome(api: &Url) -> Result<()> {
    // TODO: print welcome
    println!("SOS interactive shell");
    println!(r#"Type "help", "--help" or "-h" for command usage"#);
    println!(r#"Type "version", "--version" or "-V" for version info"#);
    println!(r#"Type "quit" or "q" to exit"#);
    println!("API: {}", api);
    Ok(())
}

async fn run() -> Result<()> {
    let args = Cli::parse();

    // Decrypt the keystore and create the client.
    let mut keystore_file = File::open(&args.keystore)?;
    let mut keystore_bytes = Vec::new();
    keystore_file.read_to_end(&mut keystore_bytes)?;
    let keystore: KeyStore = serde_json::from_slice(&keystore_bytes)?;

    let password = read_password(Some("Passphrase: "))?;
    let signing_bytes = decrypt(&keystore, &password)?;

    let signing_key: [u8; 32] = signing_bytes.as_slice().try_into()?;
    let mut signer: SingleParty = (&signing_key).try_into()?;
    let client = Client::new(args.api, &mut signer);

    welcome(client.api())?;

    read_shell(|line: String| {
        run_shell_command(&line).unwrap();
    }, Some("sos> "))?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    match run().await {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
        }
    }
    Ok(())
}
