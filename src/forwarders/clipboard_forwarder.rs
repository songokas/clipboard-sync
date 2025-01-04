use core::future::Future;
use std::collections::HashMap;

use bytes::Bytes;
use indexmap::IndexMap;
use log::info;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::{
    clipboards::{ClipboardSystem, ClipboardWriteMessage},
    defaults::{ExecutorResult, MAX_CHANNEL},
    message::GroupName,
    protocols::ProtocolReadMessage,
};

type ClipboardTypes = HashMap<ClipboardSystem, Sender<ClipboardWriteMessage>>;
type SupportedGroups = IndexMap<GroupName, (ClipboardSystem, String)>;

pub fn create_protocol_to_clipboard_forwarder(
    supported_clipboards: ClipboardTypes,
    supported_groups: SupportedGroups,
) -> (
    impl Future<Output = ExecutorResult>,
    Sender<ProtocolReadMessage>,
) {
    let (sender, receiver) = channel(MAX_CHANNEL);
    (
        protocol_to_clipboard_executor(receiver, supported_clipboards, supported_groups),
        sender,
    )
}

async fn protocol_to_clipboard_executor(
    mut receiver: Receiver<ProtocolReadMessage>,
    mut supported_clipboards: ClipboardTypes,
    supported_groups: SupportedGroups,
) -> ExecutorResult {
    let mut success_count = 0;
    loop {
        let Some(message) = receiver.recv().await else {
            break;
        };

        let Some((clipboard, destination)) = supported_groups.get(&message.group) else {
            info!("Received unsupported group {}", message.group);
            continue;
        };

        let Some(sender) = supported_clipboards.get_mut(clipboard) else {
            info!("Received unsupported group {}", message.group);
            continue;
        };

        let result = sender
            .send(ClipboardWriteMessage {
                destination: destination.clone(),
                message_type: message.message_type,
                from: message.remote.to_string(),
                data: Bytes::from(message.data),
            })
            .await;
        if result.is_err() {
            break;
        }
        success_count += 1;
    }
    Ok(("protocol to clipboard forwarder", success_count))
}
