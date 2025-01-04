use std::{
    future::Future,
    path::{Path, PathBuf},
};

#[cfg(feature = "notify-debouncer-full")]
use std::{collections::HashMap, time::Duration};

use bytes::Bytes;
#[cfg(feature = "notify-debouncer-full")]
use indexmap::IndexSet;
#[cfg(feature = "notify-debouncer-full")]
use log::trace;
use log::{debug, error, warn};
#[cfg(feature = "notify-debouncer-full")]
use notify_debouncer_full::notify::{
    event::{AccessKind, AccessMode, CreateKind, RemoveKind},
    EventKind, RecommendedWatcher, RecursiveMode,
};
#[cfg(feature = "notify-debouncer-full")]
use notify_debouncer_full::{
    new_debouncer, DebounceEventHandler, DebounceEventResult, DebouncedEvent, Debouncer,
    RecommendedCache,
};
use tokio::sync::mpsc::{channel, Receiver, Sender};
#[cfg(feature = "notify-debouncer-full")]
use tokio::{runtime::Handle, select, sync::mpsc::error::SendError};
use tokio_util::sync::CancellationToken;

use crate::{
    clipboards::{ModifiedFiles, Paths},
    defaults::{ExecutorResult, MAX_CHANNEL},
    encryption::hash,
    errors::{CliError, FilesystemError},
    filesystem::{bytes_to_dir, dir_to_bytes, files_to_bytes, read_file, write_file},
    message::MessageType,
    protocols::{StatusHandler, StatusInfo, StatusMessage},
};

use crate::clipboards::{ClipboardReadMessage, ClipboardWriteMessage};

pub fn create_filesystem_writer(
    status_sender: Sender<StatusMessage>,
    modified_files: ModifiedFiles,
    max_file_size: usize,
) -> (
    impl Future<Output = ExecutorResult>,
    Sender<ClipboardWriteMessage>,
) {
    let (sender, receiver) = channel(MAX_CHANNEL);
    (
        filesystem_write_executor(receiver, status_sender, modified_files, max_file_size),
        sender,
    )
}

async fn filesystem_write_executor(
    mut receiver: Receiver<ClipboardWriteMessage>,
    status_sender: Sender<StatusMessage>,
    modified_files: ModifiedFiles,
    max_file_size: usize,
) -> ExecutorResult {
    debug!("Starting filesystem writer");
    let mut success_count = 0;
    while let Some(message) = receiver.recv().await {
        if message.destination == "/dev/stdin" {
            debug!("Ignore writing to stdin");
            continue;
        }
        let data_size = message.data.len();
        let message_type = message.message_type;
        match write_files(message, max_file_size) {
            Ok(files) if files.is_empty() => continue,
            Ok(files) => {
                let destination = files
                    .first()
                    .expect("At least one file")
                    .to_string_lossy()
                    .to_string();
                modified_files.lock().unwrap().extend(files);
                let _ = status_sender
                    .send(
                        StatusInfo {
                            data_size,
                            message_type,
                            destination,
                            status_handler: StatusHandler::Filesystem,
                        }
                        .into_ok(),
                    )
                    .await;
                success_count += 1;
            }
            Err(e) => error!("Failed to write {e}"),
        }
    }
    Ok(("filesystem writer", success_count))
}

fn write_files(
    message: ClipboardWriteMessage,
    max_file_size: usize,
) -> Result<Vec<PathBuf>, FilesystemError> {
    let path: PathBuf = Path::new(&message.destination).to_path_buf();
    match message.message_type {
        MessageType::Text | MessageType::File if path.is_dir() => {
            bytes_to_dir(&path, message.data, &message.from, max_file_size)
        }
        MessageType::PublicKey if path.is_dir() => {
            let from = hash(&message.data);
            bytes_to_dir(&path, message.data, &from, max_file_size)
        }
        MessageType::Text | MessageType::File | MessageType::PublicKey => {
            if message.data.len() > max_file_size {
                warn!(
                    "Ignoring file {} because it contains more data {} than expected {}",
                    path.to_string_lossy(),
                    message.data.len(),
                    max_file_size
                );
                return Ok(vec![]);
            }
            write_file(&path, message.data, 0o600)?;
            Ok(vec![path])
        }
        MessageType::Files | MessageType::Directory => {
            bytes_to_dir(&path, message.data, &message.from, max_file_size)
        }
        MessageType::Handshake | MessageType::Heartbeat => Ok(vec![]),
    }
}

pub async fn create_filesystem_reader(
    sender: Sender<ClipboardReadMessage>,
    paths_to_watch: Paths,
    _modified_files: ModifiedFiles,
    read_immediately: bool,
    max_file_size: usize,
    _cancel: CancellationToken,
) -> ExecutorResult {
    debug!("Create filesystem reader {paths_to_watch:?}");
    let mut success_count = 0;
    if read_immediately {
        for (path, groups) in paths_to_watch.iter().filter(|(f, _)| f.exists()) {
            match to_bytes(path, max_file_size) {
                Ok((_, data)) if data.is_empty() => continue,
                Ok((message_type, data)) => {
                    debug!("Send clipboard on startup path={}", path.to_string_lossy());
                    sender
                        .send(ClipboardReadMessage {
                            groups: groups.clone(),
                            message_type,
                            data,
                        })
                        .await
                        .map_err(|_| CliError::ChannelClosed)?;
                    success_count += 1;
                }
                Err(_) => {
                    error!("Failed to read changes in {}", path.to_string_lossy())
                }
            }
        }
    }

    #[cfg(feature = "notify-debouncer-full")]
    {
        let (watch_sender, receiver) = channel(MAX_CHANNEL);
        let tokio_sender = TokioSender {
            runtime: Handle::current(),
            sender: watch_sender,
        };
        let mut watcher = new_debouncer(Duration::from_secs(1), None, tokio_sender).unwrap();
        watch_paths(&mut watcher, &paths_to_watch);
        file_reader_executor(
            watcher,
            receiver,
            sender,
            paths_to_watch,
            _modified_files,
            max_file_size,
            success_count,
            _cancel,
        )
        .await
    }
    #[cfg(not(feature = "notify-debouncer-full"))]
    Ok(("file reader", success_count))
}

#[cfg(feature = "notify-debouncer-full")]
#[allow(clippy::too_many_arguments)]
async fn file_reader_executor(
    mut watcher: Debouncer<RecommendedWatcher, RecommendedCache>,
    mut receiver: Receiver<DebounceEventResult>,
    sender: Sender<ClipboardReadMessage>,
    paths_to_watch: Paths,
    modified_files: ModifiedFiles,
    max_file_size: usize,
    mut success_count: u64,
    cancel: CancellationToken,
) -> ExecutorResult {
    debug!("Starting filesystem reader");

    loop {
        select! {
            _ = cancel.cancelled() => {
                debug!("File reader cancelled");
                break;
            }
            events = receiver.recv() => {
                match events {
                    Some(Ok(events)) => {
                        match handle_events(&mut watcher, &sender, &paths_to_watch, events, &modified_files, max_file_size).await {
                            Ok(c) => success_count += c,
                            Err(_) => {
                                debug!("File reader cancelled");
                                break
                            }
                        }
                    },
                    Some(Err(e)) => debug!("Filesystem error={}", e.first().map(ToString::to_string).unwrap_or_else(|| "unknown".to_string())),
                    None => {
                        debug!("File reader cancelled");
                        break
                    }
                }
            }
        }
    }
    Ok(("file reader", success_count))
}

#[cfg(feature = "notify-debouncer-full")]
async fn handle_events(
    watcher: &mut Debouncer<RecommendedWatcher, RecommendedCache>,
    sender: &Sender<ClipboardReadMessage>,
    paths_to_watch: &Paths,
    events: Vec<DebouncedEvent>,
    modified_files: &ModifiedFiles,
    max_file_size: usize,
) -> Result<u64, SendError<ClipboardReadMessage>> {
    let mut success_count = 0;
    for event in events {
        trace!("Filesystem event received {:?}", event.kind);
        match event.kind {
            EventKind::Access(AccessKind::Close(AccessMode::Write)) => {
                let Some(path) = event.paths.first() else {
                    continue;
                };

                let paths = paths_to_watch.iter().filter(|(expected_path, _)| {
                    expected_path == &path || path.starts_with(expected_path)
                });
                let groups: IndexSet<_> = paths.into_iter().flat_map(|(_, g)| g.clone()).collect();
                if groups.is_empty() {
                    continue;
                }

                if modified_files.lock().unwrap().remove(path) {
                    continue;
                }
                debug!("Path modified {}", path.to_string_lossy());

                match to_bytes(path, max_file_size) {
                    Ok((_, data)) if data.is_empty() => continue,
                    Ok((message_type, data)) => {
                        sender
                            .send(ClipboardReadMessage {
                                groups,
                                message_type,
                                data,
                            })
                            .await?;
                        success_count += 1;
                    }
                    Err(e) => {
                        error!(
                            "Failed to notify for changes in {} {e}",
                            path.to_string_lossy()
                        )
                    }
                }
            }
            // if expected directory is created lets watch it
            EventKind::Create(CreateKind::Folder | CreateKind::File) => {
                let Some(path) = event.paths.first() else {
                    continue;
                };
                if paths_to_watch.contains_key(path) {
                    match watcher.watch(path, RecursiveMode::NonRecursive) {
                        Ok(_) => {
                            debug!(
                                "Directory/file created {} watching for filesystem changes",
                                path.to_string_lossy()
                            );
                            if let Some(p) = path.parent() {
                                if let Err(e) = watcher.unwatch(p) {
                                    warn!(
                                        "Failed to unwatch parent directory {} {}",
                                        p.to_string_lossy(),
                                        e
                                    );
                                }
                            }
                        }
                        Err(e) => warn!("Watching for changes error occurred {}", e),
                    }
                }
            }
            // if expected file/directory is removed lets watch parent
            EventKind::Remove(RemoveKind::Folder | RemoveKind::File) => {
                let Some(path) = event.paths.first() else {
                    continue;
                };
                if let Some(p) = paths_to_watch.get(path).and(path.parent()) {
                    match watcher.watch(p, RecursiveMode::NonRecursive) {
                        Ok(_) => {
                            debug!(
                                "Directory/file {} removed watching for filesystem changes in {}",
                                path.to_string_lossy(),
                                p.to_string_lossy()
                            )
                        }
                        Err(e) => warn!("Watching for changes error occurred {}", e),
                    };
                }
            }
            _ => (),
        }
    }
    Ok(success_count)
}

fn to_bytes(path: &Path, max_file_size: usize) -> Result<(MessageType, Bytes), FilesystemError> {
    if path.is_dir() {
        let data = dir_to_bytes(path, max_file_size)?;
        Ok((MessageType::Directory, data))
    } else if path == Path::new("/dev/stdin") {
        let (data, _) = read_file(path, max_file_size)?;
        Ok((MessageType::File, Bytes::from(data)))
    } else {
        let data = files_to_bytes(vec![path], max_file_size)?;
        Ok((MessageType::Files, data))
    }
}

#[cfg(feature = "notify-debouncer-full")]
fn watch_paths<T>(
    watcher: &mut Debouncer<RecommendedWatcher, RecommendedCache>,
    paths_to_watch: &HashMap<PathBuf, T>,
) {
    for path in paths_to_watch.keys() {
        match watcher.watch(path, RecursiveMode::NonRecursive) {
            Ok(_) => debug!(
                "Watching for filesystem changes path={}",
                path.to_string_lossy()
            ),
            Err(e) => {
                // if no dir/file exists try parent
                let presult = if let Some(p) = path.parent().and_then(|p| p.exists().then_some(p)) {
                    watcher.watch(p, RecursiveMode::NonRecursive).map(|_| p)
                } else {
                    Err(e)
                };
                match presult {
                    Ok(parent_path) => {
                        debug!(
                            "Watching for filesystem changes in parent {} of {}",
                            parent_path.to_string_lossy(),
                            path.to_string_lossy(),
                        )
                    }
                    Err(e) => warn!(
                        "Failed to watch filesystem changes for {} {}",
                        path.to_string_lossy(),
                        e
                    ),
                };
            }
        };
    }
}

#[cfg(feature = "notify-debouncer-full")]
struct TokioSender {
    runtime: Handle,
    sender: Sender<DebounceEventResult>,
}

#[cfg(feature = "notify-debouncer-full")]
impl DebounceEventHandler for TokioSender {
    fn handle_event(&mut self, result: DebounceEventResult) {
        let _ = self
            .runtime
            .block_on(async { self.sender.send(result).await });
    }
}
