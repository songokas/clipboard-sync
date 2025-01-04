use log::debug;
use log::error;
use log::warn;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::select;
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;
use tokio::time::sleep;

use crate::defaults::ExecutorResult;
use crate::defaults::DATA_TIMEOUT;
use crate::defaults::MAX_CHANNEL;
use crate::defaults::WAIT_TIMEOUT;
use crate::encryptor::MessageEncryptor;

use crate::pools::udp_pool::UdpData;
use crate::pools::udp_pool::UdpSocketPool;
use crate::protocol::Protocol;

use crate::protocol_writers::process_send_stream_result;
use crate::protocol_writers::queue_heartbeat;
use crate::protocol_writers::StreamData;
use crate::protocol_writers::StreamError;
use crate::protocol_writers::StreamResult;
use crate::protocols::basic::send_data;
use crate::protocols::ProtocolWriteMessage;
use crate::protocols::StatusMessage;
use crate::socket::resolve_addresses;

pub fn create_basic_writer<T>(
    status_sender: Sender<StatusMessage>,
    encryptor: T,
    sockets: UdpSocketPool,
) -> (
    impl Future<Output = ExecutorResult>,
    Sender<ProtocolWriteMessage>,
)
where
    T: MessageEncryptor,
{
    let (sender, receiver) = channel(MAX_CHANNEL);
    (
        basic_writer_executor(receiver, status_sender, encryptor, sockets),
        sender,
    )
}

pub(crate) async fn basic_writer_executor<T>(
    mut receiver: Receiver<ProtocolWriteMessage>,
    status_sender: Sender<StatusMessage>,
    encryptor: T,
    sockets: UdpSocketPool,
) -> ExecutorResult
where
    T: MessageEncryptor,
{
    let mut data_streams = JoinSet::new();
    let mut new_streams: JoinSet<StreamData<Arc<UdpData>>> = JoinSet::new();
    let mut heartbeats: HashMap<(SocketAddr, SocketAddr), Instant> = HashMap::new();
    let mut success_count = 0;

    debug!("Starting writer protocol={}", Protocol::Basic);

    loop {
        sockets.cleanup(WAIT_TIMEOUT).await;
        select! {
            Some(new_stream) = new_streams.join_next(), if !new_streams.is_empty() => {

                let StreamData {stream, bound_addr, destination, group, message_type,data, heartbeat } = match new_stream {
                    Ok(stream) => stream,
                    Err(e) => {
                        debug!("Join error: {e}");
                        continue;
                    }
                };

                let data_size = data.len();
                let data = match encryptor.encrypt_message(data, &group, bound_addr, destination.addr, message_type).await {
                    Ok(d) => d,
                    Err(e) => {
                        error!("Failed to encrypt message {e}");
                        continue;
                    },
                };

                data_streams.spawn(async move {
                    let s = stream.mutex.lock().await;
                    let network_size = send_data(&stream.socket, data, destination.addr, DATA_TIMEOUT).await
                        .map_err(|error| StreamError { error, bound_addr, destination: destination.clone()})?;
                    drop(s);
                    Ok(StreamResult { stream, bound_addr, destination, group, data_size, network_size, message_type, heartbeat })
                });
            },
            message = receiver.recv() => {
                let Some(ProtocolWriteMessage {group,data,message_type,local_addresses,destination,heartbeat, server_name }) = message else {
                    break;
                };

                let Ok((local_addr, destination)) = resolve_addresses(&local_addresses, &destination, server_name.as_deref()) else {
                    continue;
                };

                let heartbeat = if local_addr.port() == 0 && heartbeat.is_some() {
                    warn!("Not sending heartbeats for temporary sockets local_addr={local_addr}");
                    None
                } else {
                    heartbeat
                };

                let Ok((stream, bound_addr)) = sockets.obtain(local_addr, destination.addr).await.inspect_err(|e| {
                    error!("Failed to obtain socket {e}");
                }) else {
                    let _ = status_sender.send(StatusMessage::from_err("Failed to obtain socket")).await;
                    continue;
                };

                let data = data.to_vec();
                new_streams.spawn(async move {
                    StreamData {stream, bound_addr, destination, group, message_type, heartbeat, data}
                });
            },
            Some(stream_finished) = data_streams.join_next(), if !data_streams.is_empty() => {
                let stream = match process_send_stream_result(stream_finished, &status_sender).await {
                    Ok(Some(stream)) => {
                        sockets.last_used(stream.bound_addr).await;
                        success_count += 1;
                        stream
                    }
                    Ok(None) => continue,
                    Err(StreamError { bound_addr, .. }) => {
                        sockets.remove(bound_addr).await;
                        continue;
                    }
                };
                if let Some((sleep_duration, stream)) = queue_heartbeat(&mut heartbeats, stream) {
                    debug!("Heartbeat prepared local_addr={} remote_addr={}", stream.bound_addr, stream.destination.addr);
                    new_streams.spawn(async move {
                        sleep(sleep_duration).await;
                        stream
                    });
                }
            }
        }
    }
    Ok(("basic writer", success_count))
}
