use core::{str, time::Duration};
use std::{future::Future, path::PathBuf, thread::sleep};

use bytes::Bytes;
use indexmap::IndexSet;
use log::{debug, error, trace};
use tokio::{
    select,
    sync::mpsc::{channel, error::SendError, Sender},
};
use tokio_util::sync::CancellationToken;

use crate::{
    clipboards::{Clipboard, ClipboardHash, ClipboardType},
    defaults::{ExecutorResult, MAX_CHANNEL},
    encryption::hash,
    errors::{CliError, ClipboardError},
    filesystem::{decode_path, files_to_bytes},
    message::{GroupName, MessageType},
};

use crate::clipboards::ClipboardReadMessage;

struct ClipboardBytes {
    hash: String,
    message_type: MessageType,
    data: Vec<u8>,
}

pub fn create_clipboard_reader(
    sender: Sender<ClipboardReadMessage>,
    groups: IndexSet<GroupName>,
    clipboard_hash: ClipboardHash,
    read_initial: bool,
    max_file_size: usize,
    cancel: CancellationToken,
) -> impl Future<Output = ExecutorResult> {
    clipboard_read_executor(
        sender,
        groups,
        clipboard_hash,
        read_initial,
        max_file_size,
        cancel,
    )
}

async fn clipboard_read_executor(
    sender: Sender<ClipboardReadMessage>,
    groups: IndexSet<GroupName>,
    clipboard_hash: ClipboardHash,
    read_initial: bool,
    max_file_size: usize,
    cancel: CancellationToken,
) -> ExecutorResult {
    debug!("Starting clipboard reader read_initial={read_initial}");
    let mut clipboard = Clipboard::new().expect("Clipboard created");
    let mut success_count = 0;
    let (clip_sender, mut clip_receiver) = channel(MAX_CHANNEL);
    if read_initial {
        if let Ok(Some(bytes)) = read_clipboard(&mut clipboard, clipboard_hash.clone(), false) {
            clip_sender
                .send(bytes)
                .await
                .map_err(|_| CliError::ChannelClosed)?
        }
    }

    let hash = clipboard_hash.clone();
    drop(clipboard);

    // detached thread on purpose
    std::thread::spawn(move || -> Result<(), SendError<ClipboardBytes>> {
        // new clipboard for osx
        let mut clipboard = Clipboard::new().expect("Clipboard created");
        loop {
            match read_clipboard(&mut clipboard, hash.clone(), true) {
                Ok(Some(bytes)) => {
                    trace!("Clipboard read {}", bytes.message_type);
                    clip_sender.blocking_send(bytes)?;
                }
                Ok(None) => (),
                Err(e) => debug!("Clipboard error: {e}"),
            }
            sleep(Duration::from_millis(500));
        }
    });

    loop {
        select! {
            _ = cancel.cancelled() => {
                debug!("Clipboard reader cancelled");
                break;
            }
            Some(ClipboardBytes { message_type, data, hash}) = clip_receiver.recv() => {
                let data = if matches!(message_type, MessageType::Files) {
                    match file_clipboard_to_bytes(data, max_file_size) {
                        Ok(d) => d,
                        Err(e) => {
                            error!("{e}");
                            continue;
                        }
                    }
                } else {
                    Bytes::from(data)
                };

                *clipboard_hash.lock().expect("Clipboard hash lock") = hash.into();
                success_count += 1;

                let Ok(_) = sender
                .send(ClipboardReadMessage {
                    groups: groups.clone(),
                    message_type,
                    data,
                })
                .await else {
                    debug!("Clipboard reader stopped");
                    break;
                };
            }
        }
    }
    Ok(("clipboard reader", success_count))
}

fn read_clipboard(
    clipboard: &mut Clipboard,
    clipboard_hash: ClipboardHash,
    block: bool,
) -> Result<Option<ClipboardBytes>, ClipboardError> {
    let data = if block {
        clipboard.wait_for_target_contents(ClipboardType::Files)
    } else {
        clipboard.get_target_contents(ClipboardType::Files)
    };
    let current_hash = clipboard_hash.lock().unwrap().clone();
    let existing_hash = current_hash.as_deref();
    match data {
        Ok(data) if !data.is_empty() => {
            let hash = hash(&data);
            trace!(
                "Clipboard files hash={hash} existing={} len={} text={}",
                existing_hash.unwrap_or("none"),
                data.len(),
                str::from_utf8(&data).unwrap_or_default()
            );
            if Some(hash.as_str()) == existing_hash {
                return Ok(None);
            }

            Ok(Some(ClipboardBytes {
                hash,
                message_type: MessageType::Files,
                data,
            }))
        }
        Ok(_) => match clipboard.get_target_contents(ClipboardType::Text) {
            Ok(data) if !data.is_empty() => {
                let hash = hash(&data);
                trace!(
                    "Clipboard text hash={hash} existing={} len={} text={}",
                    existing_hash.unwrap_or("none"),
                    data.len(),
                    str::from_utf8(&data).unwrap_or_default()
                );
                if Some(hash.as_str()) == existing_hash {
                    return Ok(None);
                }
                Ok(Some(ClipboardBytes {
                    hash,
                    message_type: MessageType::Text,
                    data,
                }))
            }
            Ok(_) => Ok(None),
            Err(e) => Err(ClipboardError::AccessError(e.to_string())),
        },
        Err(e) => Err(ClipboardError::AccessError(e.to_string())),
    }
}

fn file_clipboard_to_bytes(data: Vec<u8>, max_file_size: usize) -> Result<Bytes, ClipboardError> {
    let clipboard_contents = String::from_utf8(data)
        .map_err(|e| ClipboardError::InvalidUtf8(format!("Invalid utf-8 string provided {e}")))?;
    // debug!("Send file clipboard {}", clipboard_contents);
    let files: Vec<PathBuf> = clipboard_contents
        .lines()
        .filter_map(|p| {
            let path = p.trim_start_matches("file://");
            decode_path(path).ok()
        })
        .collect();
    files_to_bytes(files.iter().map(AsRef::as_ref).collect(), max_file_size).map_err(Into::into)
}
