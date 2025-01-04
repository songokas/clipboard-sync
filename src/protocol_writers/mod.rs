use bytes::Bytes;
use core::time::Duration;
use log::{debug, error, info, warn};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::sync::mpsc::Sender;

use crate::errors::ConnectionError;
use crate::message::{GroupName, MessageType};
use crate::multicast::resolve_multicast;
use crate::protocol::Protocol;
use crate::protocols::{ProtocolWriteMessage, StatusHandler, StatusInfo, StatusMessage};
use crate::socket::{resolve_addresses, Destination};

pub mod basic;
#[cfg(feature = "quic")]
pub mod quic;
pub mod tcp;
#[cfg(feature = "tls")]
pub mod tcp_tls;

#[derive(Debug)]
struct StreamData<T> {
    stream: T,
    bound_addr: SocketAddr,
    destination: Destination,
    group: GroupName,
    message_type: MessageType,
    heartbeat: Option<Duration>,
    data: Vec<u8>,
}

struct StreamError {
    error: ConnectionError,
    bound_addr: SocketAddr,
    destination: Destination,
}

struct StreamResult<T> {
    stream: T,
    bound_addr: SocketAddr,
    destination: Destination,
    group: GroupName,
    data_size: usize,
    network_size: usize,
    message_type: MessageType,
    heartbeat: Option<Duration>,
}

pub struct DestinationsStream {
    message_type: MessageType,
    group: String,
    local_addr: SocketAddr,
    destinations: Vec<Destination>,
    heartbeat: Option<Duration>,
    data: Bytes,
}

type SendFinishedResult<T> = Result<Result<StreamResult<T>, StreamError>, tokio::task::JoinError>;

async fn process_send_stream_result<T>(
    stream_finished: SendFinishedResult<T>,
    status_sender: &Sender<StatusMessage>,
) -> Result<Option<StreamResult<T>>, StreamError> {
    match stream_finished {
        Ok(Ok(result)) => {
            debug!(
                "Message sent data_size={} network_size={} message_type={}",
                result.data_size, result.network_size, result.message_type
            );
            let _ = status_sender
                .send(
                    StatusInfo {
                        data_size: result.data_size,
                        message_type: result.message_type,
                        destination: result.destination.host.clone(),
                        status_handler: StatusHandler::Protocol,
                    }
                    .into_ok(),
                )
                .await;
            Ok(result.into())
        }
        Ok(Err(e)) => {
            error!("Sender stream error: {}", e.error);
            let _ = status_sender
                .send(StatusMessage::from_err(e.error.to_string()))
                .await;
            Err(e)
        }
        Err(e) => {
            error!("Join error: {e}");
            Ok(None)
        }
    }
}

/// any message can trigger heartbeat as long as its above heartbeat duration
fn queue_heartbeat<T>(
    heartbeats: &mut HashMap<(SocketAddr, SocketAddr), Instant>,
    stream: StreamResult<T>,
) -> Option<(Duration, StreamData<T>)> {
    let StreamResult {
        stream,
        bound_addr,
        destination,
        group,
        heartbeat,
        ..
    } = stream;

    let heartbeat = heartbeat?;

    match heartbeats.entry((bound_addr, destination.addr)) {
        Entry::Occupied(mut entry) => {
            // prevent multiple heartbeats
            if heartbeat.is_zero() || entry.get().elapsed() < heartbeat {
                return None;
            }
            *entry.get_mut() = Instant::now();
        }
        Entry::Vacant(entry) => {
            entry.insert(Instant::now());
        }
    };

    let data = heartbeat.as_secs().to_be_bytes().to_vec();
    Some((
        heartbeat,
        StreamData {
            stream,
            bound_addr,
            destination,
            group,
            message_type: MessageType::Heartbeat,
            heartbeat: heartbeat.into(),
            data,
        },
    ))
}

pub async fn handle_incoming_data(
    message: ProtocolWriteMessage,
    protocol: Protocol,
    status_sender: Sender<StatusMessage>,
) -> Option<DestinationsStream> {
    let ProtocolWriteMessage {
        group,
        data,
        message_type,
        local_addresses,
        destination,
        heartbeat,
        server_name,
    } = message;

    let Ok((local_addr, destination)) =
        resolve_addresses(&local_addresses, &destination, server_name.as_deref())
    else {
        return None;
    };

    let destinations = if destination.addr.ip().is_multicast() {
        match resolve_multicast(
            local_addr.ip(),
            destination.addr,
            protocol,
            Duration::from_millis(1500),
        )
        .await
        {
            Ok(a) => a,
            Err(e) => {
                let _ = status_sender
                    .send(StatusMessage::from_err(format!(
                        "Unable to resolve multicast address={} {e}",
                        destination.addr
                    )))
                    .await;
                info!(
                    "Unable to resolve multicast address={} {e}",
                    destination.addr
                );
                return None;
            }
        }
    } else {
        vec![destination]
    };

    // no heartbeats
    let heartbeat = if local_addr.port() == 0 && heartbeat.is_some() {
        warn!("Not sending heartbeats for temporary sockets local_addr={local_addr}");
        None
    } else {
        heartbeat
    };

    Some(DestinationsStream {
        local_addr,
        destinations,
        heartbeat,
        message_type,
        group,
        data,
    })
}
