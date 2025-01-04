use std::{
    future::Future,
    path::{Path, PathBuf},
};

use log::{debug, error, warn};

use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::{
    clipboards::{ClipboardWriteMessage, ModifiedFiles},
    defaults::{ExecutorResult, MAX_CHANNEL},
    encryption::hash,
    errors::FilesystemError,
    filesystem::{bytes_to_dir, write_file},
    message::MessageType,
    protocols::{StatusHandler, StatusInfo, StatusMessage},
};

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
