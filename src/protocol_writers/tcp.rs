use core::ops::DerefMut;
use log::{debug, error};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpSocket;
use tokio::select;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::sleep;

use crate::defaults::{ExecutorResult, MAX_CHANNEL, WAIT_TIMEOUT};
use crate::encryptor::MessageEncryptor;
use crate::errors::ConnectionError;
use crate::pools::socket_pool::SocketState;
use crate::pools::tcp_stream_pool::{LockedStateTcpWrite, LockedTcpWrite, TcpStreamPool};
use crate::protocol::Protocol;
use crate::protocol_writers::{
    handle_incoming_data, process_send_stream_result, queue_heartbeat, DestinationsStream,
    StreamData, StreamError, StreamResult,
};
use crate::protocols::tcp::{is_closed, obtain_client_socket};
use crate::protocols::{ProtocolWriteMessage, StatusMessage};
use crate::socket::Destination;
use crate::stream::send_stream;

pub fn create_tcp_writer<T>(
    status_sender: Sender<StatusMessage>,
    encryptor: T,
    tcp_stream_pool: TcpStreamPool,
) -> (
    impl Future<Output = ExecutorResult>,
    tokio::sync::mpsc::Sender<ProtocolWriteMessage>,
)
where
    T: MessageEncryptor,
{
    let (sender, receiver) = channel(MAX_CHANNEL);
    (
        tcp_writer_executor(receiver, status_sender, encryptor, tcp_stream_pool),
        sender,
    )
}

pub(crate) async fn tcp_writer_executor<T>(
    mut receiver: Receiver<ProtocolWriteMessage>,
    status_sender: Sender<StatusMessage>,
    encryptor: T,
    streams: TcpStreamPool,
) -> ExecutorResult
where
    T: MessageEncryptor,
{
    let mut new_streams: JoinSet<Result<StreamData<Arc<Mutex<OwnedWriteHalf>>>, StreamError>> =
        JoinSet::new();
    let mut data_streams = JoinSet::new();
    let mut destination_streams = JoinSet::new();
    let mut heartbeats: HashMap<(SocketAddr, SocketAddr), Instant> = HashMap::new();
    let mut success_count = 0;

    debug!("Starting writer protocol={}", Protocol::Tcp);

    loop {
        select! {
            Some(destination_stream) = destination_streams.join_next(), if !destination_streams.is_empty() => {
                let Ok(Some(DestinationsStream { message_type, group, local_addr, destinations, heartbeat, data })) = destination_stream else {
                    continue;
                };
                for destination in destinations {
                    let Ok((socket, bound_addr)) = streams.obtain_write(local_addr, destination.addr, create_socket, is_disconnected).await.map_err(|e| {
                        error!("Failed to obtain socket {e}");
                    }) else {
                        let _ = status_sender
                        .send(StatusMessage::from_err("Failed to obtain socket"))
                        .await;
                        continue;
                    };

                    let cstreams = streams.clone();

                    let group = group.clone();
                    let data = data.to_vec();
                    new_streams.spawn(async move {
                        let mut state = socket.lock().await;
                        let stream = new_stream(cstreams, state.deref_mut(), bound_addr, &destination).await
                            .map_err(|error| StreamError { error, bound_addr, destination: destination.clone()})?;
                        Ok(StreamData {stream, group, bound_addr, destination, message_type, heartbeat, data})
                    });
                }
            },

            Some(new_stream) = new_streams.join_next(), if !new_streams.is_empty() => {

                let StreamData {stream, bound_addr, destination, group, message_type,data, heartbeat } = match new_stream {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(StreamError { bound_addr, destination, error})) => {
                        let _ = status_sender
                        .send(StatusMessage::from_err(error.to_string()))
                        .await;
                        streams.remove(bound_addr, destination.addr).await;
                        continue;
                    }
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
                    let network_size = {
                        let mut s = stream.lock().await;
                        send_stream(s.deref_mut(), data).await
                            .map_err(|error| StreamError { error, bound_addr, destination: destination.clone()})?
                    };
                    Ok(StreamResult { stream, bound_addr, destination, group, data_size, network_size, message_type, heartbeat })
                });
            },

            message = receiver.recv() => {
                let Some(message) = message else {
                    debug!("No more messages for writer");
                    break;
                };

                destination_streams.spawn(handle_incoming_data(message, Protocol::Tcp, status_sender.clone()));

            },
            Some(stream_finished) = data_streams.join_next(), if !data_streams.is_empty() => {
                let stream = match process_send_stream_result(stream_finished, &status_sender).await {
                    Ok(Some(stream)) => {
                        streams.last_used(stream.bound_addr, stream.destination.addr).await;
                        success_count += 1;
                        stream
                    }
                    Ok(None) => continue,
                    Err(StreamError { bound_addr, destination, .. }) => {
                        streams.remove(bound_addr, destination.addr).await;
                        continue;
                    }
                };
                if let Some((sleep_duration, stream)) = queue_heartbeat(&mut heartbeats, stream) {
                    new_streams.spawn(async move {
                        sleep(sleep_duration).await;
                        Ok(stream)
                    });
                }
            }
        }
        streams.cleanup(WAIT_TIMEOUT).await;
    }

    Ok(("tcp writer", success_count))
}

async fn new_stream(
    tcp_stream_pool: TcpStreamPool,
    state: &mut SocketState<LockedTcpWrite, TcpSocket>,
    bound_addr: SocketAddr,
    destination: &Destination,
) -> Result<LockedTcpWrite, ConnectionError> {
    match state {
        SocketState::NotConnected(None) => Err(ConnectionError::NotConnected(destination.addr)),
        SocketState::NotConnected(endpoint) => {
            let endpoint = endpoint.take().expect("Must not be empty");
            debug!(
                "Connect local_addr={bound_addr} remote_addr={} server_name={}",
                destination.addr(),
                destination.host()
            );
            let stream = endpoint.connect(destination.addr).await.inspect_err(|e| {
                error!("Unable to connect to remote {} {e}", destination.addr);
            })?;

            let (reader, writer) = stream.into_split();
            let stream = Arc::new(Mutex::new(writer));
            *state = SocketState::Connected(stream.clone());
            // find a better way
            tcp_stream_pool.add_reader(bound_addr, reader).await?;
            Ok(stream)
        }
        SocketState::Connected(stream) => {
            debug!(
                "Using existing connection local_addr={bound_addr} remote_addr={} server_name={}",
                destination.addr(),
                destination.host()
            );
            Ok(stream.clone())
        }
    }
}

pub async fn create_socket<T>(
    local_addr: SocketAddr,
    _remote_addr: SocketAddr,
) -> Result<(Mutex<SocketState<Arc<Mutex<T>>, TcpSocket>>, SocketAddr), ConnectionError> {
    let socket = obtain_client_socket(local_addr)?;
    let bind_addr = socket.local_addr().expect("Bound address");
    Ok((
        Mutex::new(SocketState::NotConnected(Some(socket))),
        bind_addr,
    ))
}

async fn is_disconnected(socket_state: Arc<LockedStateTcpWrite>) -> bool {
    match socket_state.try_lock().as_deref() {
        Ok(SocketState::Connected(s)) => match s.try_lock().as_deref_mut() {
            Ok(s) => s.peer_addr().is_err() || is_closed(s).await,
            _ => false,
        },
        Ok(SocketState::NotConnected(None)) => true,
        _ => false,
    }
}
