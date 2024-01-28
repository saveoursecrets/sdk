use crate::{helpers::account::resolve_user, Result};
use clap::Subcommand;
use kdam::{tqdm, BarExt, RowManager};
use sos_net::{
    sdk::{
        account::Account,
        identity::AccountRef,
    },
};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print the file transfers queue.
    Transfers {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,
    },
    /// Show inflight file transfers.
    Progress {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,
    },
}

/// Handle sync commands.
pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Transfers { account } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let owner = user.read().await;
            let transfers = owner.transfers().await?;
            let transfers = transfers.read().await;
            let queue = transfers.queue();
            if queue.is_empty() {
                println!("No queued file transfers");
            } else {
                for (file, ops) in queue {
                    println!("{}", file);
                }
            }
        }
        Command::Progress { account } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let owner = user.read().await;
            let transfers = owner.inflight_transfers().await?;
            let inflight = transfers.inflight();
            let inflight = inflight.read().await;

            if inflight.is_empty() {
                println!("No inflight transfers");
            } else {
                let request_ids =
                    inflight.keys().copied().collect::<Vec<_>>();

                let progress = transfers.progress();
                let progress = progress.read().await;

                let mut channels = Vec::new();
                for id in request_ids {
                    if let (Some(op), Some(tx)) =
                        (inflight.get(&id), progress.get(&id))
                    {
                        channels.push((op.clone(), tx.subscribe()));
                    }
                }

                drop(inflight);
                drop(progress);
                
                let manager =
                    Arc::new(Mutex::new(RowManager::new(5)));
                let mut threads = Vec::new();

                for (inflight_op, mut rx) in channels {
                    let mgr = Arc::clone(&manager);
                    threads.push(std::thread::spawn(move || {
                        tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .unwrap()
                            .block_on(async move {
                                let mut pb = tqdm!(
                                    unit_scale = true,
                                    unit_divisor = 1024,
                                    unit = "B"
                                );
                                let name = inflight_op.file
                                    .file_name().to_string();
                                pb.set_description(format!("{}", &name[0..8]));
                                
                                let index = {
                                    let mut writer = mgr.lock().await;
                                    writer.push(pb)?
                                };

                                let mut pb = {
                                    let mut writer = mgr.lock().await;
                                    writer.get_mut(index).unwrap().clone()
                                };

                                while let Ok((transferred, total)) =
                                    rx.recv().await
                                {
                                    if let Some(total) = total {
                                        pb.total = total as usize;
                                        pb.update_to(transferred as usize)?;
                                        if total == transferred {
                                            pb.clear()?;
                                            break;
                                        }
                                    } else {
                                        break;
                                    }
                                }

                                Ok::<(), crate::Error>(())
                            })
                            .unwrap();
                    }));
                }

                for thread in threads {
                    let _ = thread.join();
                }
            }
        }
    }
    Ok(())
}

