use crate::{helpers::account::resolve_user, Error, Result};
use clap::Subcommand;
use human_bytes::human_bytes;
use kdam::{tqdm, BarExt, RowManager};
use sos_net::{
    client::{NetworkAccount, RemoteSync, SyncOptions},
    sdk::{
        account::Account,
        identity::AccountRef,
        sync::{Origin, SyncStatus, SyncStorage},
        url::Url,
    },
};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

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
                    if let (Some(op), Some(tx)) = (inflight.get(&id), progress.get(&id)) {
                        channels.push((op.clone(), tx.subscribe()));
                    }
                }

                drop(inflight);
                drop(progress);

                let manager = Arc::new(
                    Mutex::new(
                        RowManager::from_window_size()));

                for (inflight_op, mut rx) in channels {
                    //println!("op: {:#?}", inflight_op);
                    //
                    let mgr = Arc::clone(&manager);
                    
                    std::thread::spawn(move || {
                        tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap()
                        .block_on(
                            async move {
                                let mut index: Option<usize> = None;
                                while let Ok((transferred, total)) =
                                    rx.recv().await
                                {
                                    if let Some(total) = total {
                                        let mut pb = if let Some(idx) = index {
                                            let mut writer = mgr.lock().await;
                                            writer.get_mut(idx).unwrap().clone()
                                        } else {
                                            let pb = tqdm!(
                                                total = total as usize,
                                                unit_scale = true,
                                                unit_divisor = 1024,
                                                unit = "B"
                                            );
                                            let mut writer = mgr.lock().await;
                                            let idx = writer.push(pb)?;
                                            index = Some(idx);
                                            writer.get_mut(idx).unwrap().clone()
                                        };

                                        pb.update_to(transferred as usize)?;
                                        if total == transferred {
                                            pb.clear()?;
                                            break;
                                        }

                                        /*
                                        if !total_set {
                                            pb.total = total as usize;
                                            println!("total: {}", total);
                                            total_set = true;
                                        }
                                        */
                                    } else {
                                        break;
                                    }

                                }
                                Ok::<(), crate::Error>(())
                            }

                        ).unwrap();
                    });
                }
            }
        }
    }
    Ok(())
}
