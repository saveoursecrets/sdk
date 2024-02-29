use crate::{
    helpers::{
        account::resolve_user,
        messages::{fail, success, warn},
        readline::clear_screen,
        PROGRESS_MONITOR,
    },
    Result,
};
use clap::Subcommand;
use futures::{select, FutureExt};
use kdam::{tqdm, BarExt, RowManager};
use sos_net::sdk::prelude::*;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{broadcast, Mutex};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Verify the integrity of external files.
    Integrity {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,
    },
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
        Command::Integrity { account } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let owner = user.read().await;
            let paths = owner.paths();
            let files = owner.file_log().await?;
            let files = files.read().await;
            let mut rx =
                integrity_report(paths, &*files, num_cpus::get()).await?;

            let mut progress = HashMap::new();
            let mut failures = HashMap::new();
            let mut manager = RowManager::from_window_size();

            while let Some(event) = rx.recv().await {
                let event = event?;
                match event {
                    IntegrityReportEvent::Begin(_) => {}
                    IntegrityReportEvent::Failure(file, reason) => {
                        failures.insert(file, reason);
                    }
                    IntegrityReportEvent::OpenFile(file, total) => {
                        let mut pb = tqdm!(
                            total = total as usize,
                            unit_scale = true,
                            unit_divisor = 1024,
                            unit = "B"
                        );
                        let name = file.file_name().to_string();
                        pb.set_description((name[0..8]).to_string());

                        let idx = manager.push(pb)?;
                        progress.insert(file, idx);
                    }
                    IntegrityReportEvent::ReadFile(file, amount) => {
                        if let Some(idx) = progress.get(&file) {
                            if let Some(pb) = manager.get_mut(*idx) {
                                pb.update(amount)?;
                            }
                        }
                    }
                    IntegrityReportEvent::CloseFile(file) => {
                        progress.remove(&file);
                    }
                }
            }

            clear_screen()?;

            if failures.is_empty() {
                success("Files ok");
            } else {
                for (_, failure) in failures {
                    match failure {
                        FailureReason::Missing(path) => {
                            fail(format!("missing {}", path.display()));
                        }
                        FailureReason::Corrupted { path, .. } => {
                            fail(format!("corrupted {}", path.display()));
                        }
                    }
                }
            }
        }
        Command::Transfers { account } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let owner = user.read().await;
            let transfers = owner.transfers().await?;
            let transfers = transfers.read().await;
            let queue = transfers.queue();
            if queue.is_empty() {
                println!("No queued file transfers");
            } else {
                // Group by folder
                let mut grouped = HashMap::new();
                for (file, ops) in queue {
                    if let Some(summary) =
                        owner.find(|s| s.id() == file.vault_id()).await
                    {
                        let secrets =
                            grouped.entry(summary).or_insert(HashMap::new());
                        let files =
                            secrets.entry(file.secret_id()).or_insert(vec![]);
                        files.push((file.file_name(), ops));
                    } else {
                        warn(format!("folder missing {}", file.vault_id(),));
                    }
                }

                for (folder, secrets) in grouped {
                    println!("[{}]", folder.name());
                    for (secret_id, files) in secrets {
                        println!("> {}", secret_id);
                        for (name, ops) in files {
                            println!("  {}", name);
                            println!("  {}", serde_json::to_string(&ops)?);
                        }
                    }
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
                    Arc::new(Mutex::new(RowManager::from_window_size()));
                let mut threads = Vec::new();

                // Shutdown channel for ctrlc handling
                let (shutdown_tx, _) = broadcast::channel::<()>(1);

                // Update the global so ctrlc handler will
                // send an event on the shutdown channel
                {
                    let mut mon = PROGRESS_MONITOR.lock();
                    *mon = Some(shutdown_tx.clone());
                }

                for (inflight_op, rx) in channels {
                    let mgr = Arc::clone(&manager);
                    let shutdown = shutdown_tx.subscribe();
                    threads.push(spawn_file_progress(
                        inflight_op,
                        mgr,
                        shutdown,
                        rx,
                    ));
                }

                for thread in threads {
                    let _ = thread.join();
                }

                // Clear the shutdown channel as we are done
                {
                    let mut mon = PROGRESS_MONITOR.lock();
                    *mon = None;
                }
            }
        }
    }
    Ok(())
}

fn spawn_file_progress(
    inflight_op: InflightOperation,
    mgr: Arc<Mutex<RowManager>>,
    mut shutdown: broadcast::Receiver<()>,
    mut rx: broadcast::Receiver<(u64, Option<u64>)>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
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
                let name =
                    inflight_op.file.file_name().to_string();
                pb.set_description((
                    name[0..8]
                ).to_string());

                let index = {
                    let mut writer = mgr.lock().await;
                    writer.push(pb)?
                };

                loop {
                    select! {
                        _ = shutdown.recv().fuse() => {
                            break;
                        }
                        event = rx.recv().fuse() => {
                            match event {
                                Ok((transferred, total)) => {
                                    if let Some(total) = total {
                                        let mut writer = mgr.lock().await;
                                        let pb = writer.get_mut(index).unwrap();
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
                                _ => break,
                            }
                        }
                    }
                }

                Ok::<(), crate::Error>(())
            })
            .unwrap();
    })
}
