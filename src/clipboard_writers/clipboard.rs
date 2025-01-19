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
        ClipboardTargets, ClipboardWriteMessage,
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
    let (clip_sender, mut clip_receiver) = channel(MAX_CHANNEL);

    // detached thread on purpose
    std::thread::spawn(move || {
        let mut clipboard = Clipboard::new().expect("Clipboard created");
        while let Some(targets) = clip_receiver.blocking_recv() {
            if let Err(e) = clipboard.set_multiple_targets(targets) {
                error!("Clipboard failed to write to clipboard {e}")
            }
        }
    });

    let data_dir = get_app_dir(app_dir).map(|p| p.join("data"))?;
    let mut success_count = 0;
    while let Some(message) = receiver.recv().await {
        let data_size = message.data.len();
        let message_type = message.message_type;
        match bytes_to_clipboard(
            &clip_sender,
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
    sender: &Sender<ClipboardTargets>,
    message: ClipboardWriteMessage,
    clipboard_hash: &mut ClipboardHash,
    data_dir: &Path,
    max_file_size: usize,
) -> Result<(), ClipboardError> {
    match &message.message_type {
        MessageType::Text | MessageType::PublicKey => {
            *clipboard_hash.lock().expect("Clipboard hash lock") = hash(&message.data).into();

            sender
                .send(create_text_targets(message.data))
                .await
                .map_err(|_| {
                    ClipboardError::SetError("Unable to send data to clipboard".to_string())
                })?
        }
        MessageType::File | MessageType::Files | MessageType::Directory => {
            let data_dir = data_dir.join(sanitise(&message.from));
            let files_created =
                bytes_to_dir(&data_dir, message.data, &message.from, max_file_size)?;
            let (clipboards, hash_str) = create_targets_for_cut_files(files_created);
            *clipboard_hash.lock().expect("Clipboard hash lock") = hash_str.into();

            sender.send(clipboards).await.map_err(|_| {
                ClipboardError::SetError("Unable to send data to clipboard".to_string())
            })?;
        }
        MessageType::Handshake | MessageType::Heartbeat => (),
    };
    Ok(())
}
