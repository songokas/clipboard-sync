use core::future::Future;
use std::collections::HashMap;

use log::{debug, trace, warn};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::{
    clipboards::ClipboardReadMessage,
    defaults::{ExecutorResult, MAX_CHANNEL},
    message::{GroupHosts, GroupName},
    protocol::Protocol,
    protocols::ProtocolWriteMessage,
};

type ProtocolTypes = HashMap<Protocol, Sender<ProtocolWriteMessage>>;
type SupportedGroups = HashMap<GroupName, GroupHosts>;

pub fn create_clipboard_to_protocol_forwarder(
    supported_protocols: ProtocolTypes,
    supported_groups: SupportedGroups,
) -> (
    impl Future<Output = ExecutorResult>,
    Sender<ClipboardReadMessage>,
) {
    let (sender, receiver) = channel(MAX_CHANNEL);
    (
        clipboard_to_protocol_executor(receiver, supported_protocols, supported_groups),
        sender,
    )
}

async fn clipboard_to_protocol_executor(
    mut receiver: Receiver<ClipboardReadMessage>,
    mut supported_protocols: ProtocolTypes,
    supported_groups: SupportedGroups,
) -> ExecutorResult {
    debug!(
        "Starting clipboard to protocol forwarder protocol_types={:?} groups={:?}",
        supported_protocols.keys(),
        supported_groups.keys()
    );
    let mut success_count = 0;
    loop {
        let Some(message) = receiver.recv().await else {
            break;
        };

        'main: for group in message.groups {
            let Some(config) = supported_groups.get(&group) else {
                warn!("Received unsupported group {group}");
                continue;
            };
            let Some(sender) = supported_protocols.get_mut(&config.protocol) else {
                warn!("Received unsupported group {group}");
                continue;
            };

            for (destination, server_name) in config.remote_addresses.clone() {
                // ignore destinations with 0 port specified
                if destination.ends_with(":0") {
                    trace!("Ignore destination={destination}. No port specified");
                    continue;
                }
                let result = sender
                    .send(ProtocolWriteMessage {
                        group: group.clone(),
                        local_addresses: config.local_addresses.clone(),
                        destination,
                        server_name,
                        message_type: message.message_type,
                        heartbeat: config.heartbeat,
                        data: message.data.clone(),
                    })
                    .await;
                if result.is_err() {
                    break 'main;
                }
                success_count += 1;
            }
        }
    }
    Ok(("clipboard to protocol forwarder", success_count))
}
