use crate::{helpers::readline::read_password, Result};
use clap::Subcommand;
use sos_ipc::{
    native_bridge::{self, NativeBridgeOptions},
    remove_socket_file, CommandOutcome, IpcRequest,
    LocalAccountAuthenticateCommand, LocalAccountIpcService,
    LocalAccountServiceDelegate, LocalAccountSocketServer, SocketClient,
};
use sos_net::sdk::{
    crypto::AccessKey,
    prelude::{
        Account, Address, Identity, LocalAccount, LocalAccountSwitcher,
        IPC_CLI_SOCKET_NAME,
    },
};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::RwLock;

const CLI_EXTENSION_ID: &str = "com.saveoursecrets.sos";

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start an IPC server.
    Server {
        /// Socket name.
        #[clap(short, long)]
        socket: Option<String>,
    },
    /// Send requests to an IPC server or bridge.
    Send {
        /// Socket name.
        #[clap(short, long)]
        socket: Option<String>,

        /// Path to to the native bridge command.
        #[clap(short, long)]
        command: Option<PathBuf>,

        /// Native bridge arguments.
        #[clap(short, long)]
        arguments: Vec<String>,

        /// Request command.
        #[clap(subcommand)]
        cmd: SendCommand,
    },
    /// Start a native bridge.
    #[clap(alias = "bridge")]
    NativeBridge {
        /// Socket name.
        #[clap(short, long)]
        socket: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum SendCommand {
    /// List accounts request.
    ListAccounts,
    /// Authenticate request.
    #[clap(alias = "auth")]
    Authenticate {
        /// Account address.
        #[clap(short, long)]
        address: Address,
    },
}

impl From<SendCommand> for IpcRequest {
    fn from(value: SendCommand) -> Self {
        match value {
            SendCommand::ListAccounts => IpcRequest::ListAccounts,
            SendCommand::Authenticate { address } => {
                IpcRequest::Authenticate { address }
            }
        }
    }
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Server { socket } => {
            let mut accounts = LocalAccountSwitcher::new();
            let disc_accounts = Identity::list_accounts(None).await?;
            for identity in disc_accounts {
                let account = LocalAccount::new_unauthenticated(
                    *identity.address(),
                    None,
                )
                .await?;
                accounts.add_account(account);
            }

            let (delegate, commands) = LocalAccountServiceDelegate::new(16);
            let auth_rx = commands.authenticate;

            tokio::task::spawn(async move { authenticate(auth_rx).await });

            let service = Arc::new(RwLock::new(LocalAccountIpcService::new(
                Arc::new(RwLock::new(accounts)),
                delegate,
            )));

            let socket_name = socket
                .as_ref()
                .map(|s| &s[..])
                .unwrap_or(IPC_CLI_SOCKET_NAME);

            remove_socket_file(socket_name);
            LocalAccountSocketServer::listen(socket_name, service).await?;
        }
        Command::Send {
            socket,
            cmd,
            command,
            arguments,
        } => {
            if let Some(command) = command {
                send_bridge(command, arguments, cmd).await?;
            } else {
                send_ipc(socket, cmd).await?;
            }
        }
        Command::NativeBridge { socket } => {
            let socket_name = socket
                .as_ref()
                .map(|s| &s[..])
                .unwrap_or(IPC_CLI_SOCKET_NAME);
            let mut options =
                NativeBridgeOptions::new(CLI_EXTENSION_ID.to_string());
            options.socket_name = Some(socket_name.to_string());
            native_bridge::run(options).await?;
        }
    }
    Ok(())
}

async fn send_ipc(socket: Option<String>, cmd: SendCommand) -> Result<()> {
    let socket_name = socket
        .as_ref()
        .map(|s| &s[..])
        .unwrap_or(IPC_CLI_SOCKET_NAME);

    let mut client = SocketClient::connect(&socket_name).await?;
    let request = cmd.into();
    let response = client.send_request(request).await?;
    serde_json::to_writer_pretty(std::io::stdout(), &response)?;
    Ok(())
}

async fn send_bridge(
    command: PathBuf,
    arguments: Vec<String>,
    cmd: SendCommand,
) -> Result<()> {
    let request = cmd.into();
    let response = native_bridge::send(command, arguments, &request).await?;
    serde_json::to_writer_pretty(std::io::stdout(), &response)?;
    Ok(())
}

async fn authenticate(
    mut auth_rx: tokio::sync::mpsc::Receiver<LocalAccountAuthenticateCommand>,
) {
    while let Some(mut command) = auth_rx.recv().await {
        let outcome = try_authenticate(&mut command).await;
        if let Err(_) = command.result.send(outcome) {
            tracing::warn!("auth command send failed");
        }
    }
}

async fn try_authenticate(
    command: &mut LocalAccountAuthenticateCommand,
) -> CommandOutcome {
    let mut accounts = command.accounts.write().await;
    if let Some(account) = accounts
        .iter_mut()
        .find(|a| a.address() == &command.address)
    {
        if account.is_authenticated().await {
            return CommandOutcome::AlreadyAuthenticated;
        }

        tracing::info!("authenticate account {}", account.address(),);
        let mut attempts = 0;
        loop {
            if attempts == 3 {
                tracing::warn!("authentication aborted, too many attempts");
                return CommandOutcome::Exhausted;
            }
            if let Ok(password) = read_password(None) {
                attempts += 1;
                let key: AccessKey = password.into();
                if let Ok(_) = account.sign_in(&key).await {
                    return CommandOutcome::Success;
                } else {
                    tracing::warn!("incorrect password");
                    continue;
                }
            } else {
                return CommandOutcome::InputError;
            }
        }
    } else {
        CommandOutcome::NotFound
    }
}
