use crate::{helpers::readline::read_password, Result};
use clap::Subcommand;
use sos_ipc::{
    remove_socket_file, AppIntegration, AuthenticateOutcome,
    LocalAccountAuthenticateCommand, LocalAccountIpcService,
    LocalAccountSocketServer, SocketClient,
};
use sos_net::sdk::{
    crypto::AccessKey,
    prelude::{
        Account, Address, Identity, LocalAccount, LocalAccountSwitcher,
        IPC_CLI_SOCKET_NAME,
    },
};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start an IPC server.
    Server {
        /// Socket name.
        #[clap(short, long)]
        socket: Option<String>,
    },
    /// Send requests to an IPC server.
    Client {
        /// Socket name.
        #[clap(short, long)]
        socket: Option<String>,
        /// Request command.
        #[clap(subcommand)]
        cmd: ClientCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum ClientCommand {
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
            let (auth_tx, auth_rx) = tokio::sync::mpsc::channel::<
                LocalAccountAuthenticateCommand,
            >(16);

            tokio::task::spawn(async move { authenticate(auth_rx).await });

            let delegate = LocalAccountIpcService::new_delegate(auth_tx);
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
        Command::Client { socket, cmd } => {
            let socket_name = socket
                .as_ref()
                .map(|s| &s[..])
                .unwrap_or(IPC_CLI_SOCKET_NAME);

            let mut client = SocketClient::connect(&socket_name).await?;
            match cmd {
                ClientCommand::ListAccounts => {
                    let accounts = client.list_accounts().await?;
                    serde_json::to_writer_pretty(
                        std::io::stdout(),
                        &accounts,
                    )?;
                }
                ClientCommand::Authenticate { address } => {
                    println!("Sending auth {}", address);
                    let outcome = client.authenticate(address).await?;
                    serde_json::to_writer_pretty(
                        std::io::stdout(),
                        &outcome,
                    )?;
                }
            }
        }
    }
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
) -> AuthenticateOutcome {
    let mut accounts = command.accounts.write().await;
    if let Some(account) = accounts
        .iter_mut()
        .find(|a| a.address() == &command.address)
    {
        if account.is_authenticated().await {
            return AuthenticateOutcome::AlreadyAuthenticated;
        }

        tracing::info!("authenticate account {}", account.address(),);
        let mut attempts = 0;
        loop {
            if attempts == 3 {
                tracing::warn!("authentication aborted, too many attempts");
                return AuthenticateOutcome::Exhausted;
            }
            if let Ok(password) = read_password(None) {
                attempts += 1;
                let key: AccessKey = password.into();
                if let Ok(_) = account.sign_in(&key).await {
                    return AuthenticateOutcome::Success;
                } else {
                    tracing::warn!("incorrect password");
                    continue;
                }
            } else {
                return AuthenticateOutcome::InputError;
            }
        }
    } else {
        AuthenticateOutcome::NotFound
    }
}
