use std::{
    future::Future,
    path::{Path, PathBuf},
};

use log::{debug, error, trace};
use sanitise_file_name::sanitise;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::{
    clipboards::{
        create_targets_for_cut_files, create_text_targets, Clipboard, ClipboardHash,
        ClipboardWriteMessage,
    },
    config::get_app_dir,
    defaults::{ExecutorResult, CLIPBOARD_NAME, MAX_CHANNEL},
    encryption::hash,
    errors::ClipboardError,
    filesystem::bytes_to_dir,
    message::MessageType,
    protocols::{StatusHandler, StatusInfo, StatusMessage},
};

pub fn create_clipboard_writer(
    status_sender: Sender<StatusMessage>,
    clipboard_hash: ClipboardHash,
    app_dir: Option<PathBuf>,
    max_file_size: usize,
) -> (
    impl Future<Output = ExecutorResult>,
    Sender<ClipboardWriteMessage>,
) {
    let (sender, receiver) = channel(MAX_CHANNEL);
    (
        clipboard_write_executor(
            receiver,
            status_sender,
            clipboard_hash,
            app_dir,
            max_file_size,
        ),
        sender,
    )
}

async fn clipboard_write_executor(
    mut receiver: Receiver<ClipboardWriteMessage>,
    status_sender: Sender<StatusMessage>,
    mut clipboard_hash: ClipboardHash,
    app_dir: Option<PathBuf>,
    max_file_size: usize,
) -> ExecutorResult {
    debug!("Starting clipboard writer");
    let mut clipboard = Clipboard::new().expect("Clipboard created");
    let data_dir = get_app_dir(app_dir).map(|p| p.join("data"))?;
    let mut success_count = 0;
    while let Some(message) = receiver.recv().await {
        let data_size = message.data.len();
        let message_type = message.message_type;
        match bytes_to_clipboard(
            &mut clipboard,
            message,
            &mut clipboard_hash,
            &data_dir,
            max_file_size,
        )
        .await
        {
            Ok(_) => {
                trace!("Clipboard write");
                success_count += 1;
                let _ = status_sender
                    .send(
                        StatusInfo {
                            data_size,
                            message_type,
                            destination: CLIPBOARD_NAME.to_string(),
                            status_handler: StatusHandler::Clipboard,
                        }
                        .into_ok(),
                    )
                    .await;
            }
            Err(e) => error!("Clipboard failed to write to clipboard {e}"),
        }
    }
    Ok(("clipboard writer", success_count))
}

async fn bytes_to_clipboard(
    clipboard: &mut Clipboard,
    message: ClipboardWriteMessage,
    clipboard_hash: &mut ClipboardHash,
    data_dir: &Path,
    max_file_size: usize,
) -> Result<(), ClipboardError> {
    match &message.message_type {
        MessageType::Text | MessageType::PublicKey => {
            *clipboard_hash.lock().expect("Clipboard hash lock") = hash(&message.data).into();
            clipboard
                .set_multiple_targets(create_text_targets(message.data))
                .map_err(|err| ClipboardError::SetError((*err).to_string()))?
        }
        MessageType::File | MessageType::Files | MessageType::Directory => {
            let data_dir = data_dir.join(sanitise(&message.from));
            let files_created =
                bytes_to_dir(&data_dir, message.data, &message.from, max_file_size)?;
            let (clipboards, hash_str) = create_targets_for_cut_files(files_created);
            let clipboards = clipboards
                .into_iter()
                .map(|(k, v)| (k, v.into_bytes()))
                .collect();
            *clipboard_hash.lock().expect("Clipboard hash lock") = hash_str.into();

            clipboard
                .set_multiple_targets(clipboards)
                .map_err(|err| ClipboardError::SetError((*err).to_string()))?;
        }
        MessageType::Handshake | MessageType::Heartbeat => (),
    };
    Ok(())
}
