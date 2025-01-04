use log::{debug, error};
use tokio::select;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::sleep;

use core::future::Future;
use quinn::{Connection, Endpoint};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::Instant;

use crate::certificate::OptionalCertificateResult;
use crate::defaults::{ExecutorResult, MAX_CHANNEL, WAIT_TIMEOUT};
use crate::encryptor::MessageSerializer;
use crate::errors::ConnectionError;
use crate::pools::connection_pool::ConnectionPool;
use crate::pools::socket_pool::SocketState;
use crate::protocol::Protocol;

use crate::protocol_writers::{
    handle_incoming_data, process_send_stream_result, queue_heartbeat, DestinationsStream,
    StreamData, StreamError, StreamResult,
};
use crate::protocols::quic::{configure_client, obtain_client_endpoint, send_stream};
use crate::protocols::{ProtocolWriteMessage, StatusMessage};
use crate::socket::Destination;

pub fn create_quic_writer<T>(
    status_sender: Sender<StatusMessage>,
    encryptor: T,
    clonable_udp_pool: ConnectionPool,
    obtain_certs: impl Fn() -> OptionalCertificateResult + Clone,
) -> (
    impl Future<Output = ExecutorResult>,
    tokio::sync::mpsc::Sender<ProtocolWriteMessage>,
)
where
    T: MessageSerializer,
{
    let (sender, receiver) = channel(MAX_CHANNEL);
    (
        quic_writer_executor(
            receiver,
            status_sender,
            encryptor,
            clonable_udp_pool,
            obtain_certs,
        ),
        sender,
    )
}

pub(crate) async fn quic_writer_executor<T>(
    mut receiver: Receiver<ProtocolWriteMessage>,
    status_sender: Sender<StatusMessage>,
    encryptor: T,
    connections: ConnectionPool,
    obtain_certs: impl Fn() -> OptionalCertificateResult + Clone,
) -> ExecutorResult
where
    T: MessageSerializer,
{
    debug!("Starting writer protocol={}", Protocol::Quic);

    let mut data_streams = JoinSet::new();
    let mut destination_streams = JoinSet::new();
    let mut new_streams: JoinSet<Result<StreamData<Arc<Connection>>, StreamError>> = JoinSet::new();
    let mut heartbeats: HashMap<(SocketAddr, SocketAddr), Instant> = HashMap::new();
    let mut success_count = 0;

    let obtain_endpoint = |local_addr: SocketAddr, _| {
        let obtain_certs = obtain_certs.clone();
        let pool = connections.clone();
        async move {
            let endpoint = match pool.server_endpoint(local_addr).await {
                Some(mut e) => {
                    e.set_default_client_config(configure_client(obtain_certs()?)?);
                    e
                }
                None => obtain_client_endpoint(local_addr, obtain_certs()?)?,
            };
            let bound_address = endpoint.local_addr().expect("Bound address");
            Ok((
                Mutex::new(SocketState::NotConnected(endpoint.into())),
                bound_address,
            ))
        }
    };

    loop {
        connections.cleanup(WAIT_TIMEOUT).await;

        select! {
            Some(destination_stream) = destination_streams.join_next(), if !destination_streams.is_empty() => {
                let Ok(Some(DestinationsStream { message_type, group, local_addr, destinations, heartbeat, data })) = destination_stream else {
                    continue;
                };
                for destination in destinations {
                    let Ok((socket, bound_addr)) = connections.obtain(local_addr, destination.addr, obtain_endpoint).await.inspect_err(|e| {
                        error!("Failed to obtain socket {e}");
                    }) else {
                        let _ = status_sender.send(StatusMessage::from_err("Failed to obtain socket")).await;
                        continue;
                    };

                    let group = group.clone();
                    let data = data.to_vec();
                    let spool = connections.clone();
                    new_streams.spawn(async move {
                        let mut state = socket.lock().await;
                        let (stream, new) = new_stream(state.deref_mut(), bound_addr, &destination).await
                            .map_err(|error| StreamError { error, bound_addr, destination: destination.clone()})?;
                        if new {
                            spool.notify();
                        }
                        Ok(StreamData {stream, bound_addr, destination, group, message_type, heartbeat, data})
                    });
                }
            },
            Some(new_stream) = new_streams.join_next(), if !new_streams.is_empty() => {

                let StreamData {stream, bound_addr, destination, group, message_type,data, heartbeat } = match new_stream {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(StreamError { bound_addr, destination, error })) => {
                        let _ = status_sender
                        .send(StatusMessage::from_err(error.to_string()))
                        .await;
                        connections.remove(bound_addr, destination.addr).await;
                        continue;
                    }
                    Err(e) => {
                        debug!("Join error: {e}");
                        continue;
                    }
                };

                let data_size = data.len();
                let data = match encryptor.serialize_message(data, group.clone(), message_type).await {
                    Ok(d) => d,
                    Err(e) => {
                        error!("Failed to serialize message {e}");
                        continue;
                    },
                };

                data_streams.spawn(async move {
                    let network_size = send_stream(&stream, data).await.map_err(|error| StreamError { error, bound_addr, destination: destination.clone() })?;
                    Ok(StreamResult { stream, bound_addr, destination, group, data_size, network_size, message_type, heartbeat })
                });
            },
            message = receiver.recv() => {
                let Some(message) = message else {
                    debug!("No more messages for writer");
                    break;
                };

                destination_streams.spawn(handle_incoming_data(message, Protocol::Quic, status_sender.clone()));


            },
            Some(stream_finished) = data_streams.join_next(), if !data_streams.is_empty() => {
                let stream = match process_send_stream_result(stream_finished, &status_sender).await {
                    Ok(Some(stream)) => {
                        success_count += 1;
                        connections.last_used(stream.bound_addr, stream.destination.addr).await;
                        stream
                    }
                    Ok(None) => continue,
                    Err(StreamError { bound_addr, destination, .. }) => {
                        connections.remove(bound_addr, destination.addr).await;
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
    }
    Ok(("quic writer count", success_count))
}

async fn new_stream(
    state: &mut SocketState<Arc<Connection>, Endpoint>,
    bound_addr: SocketAddr,
    destination: &Destination,
) -> Result<(Arc<Connection>, bool), ConnectionError> {
    match state {
        SocketState::NotConnected(None) => Err(ConnectionError::NotConnected(destination.addr)),
        SocketState::NotConnected(endpoint) => {
            let endpoint = endpoint.take().expect("Must not be empty");
            debug!(
                "Connect local_addr={bound_addr} remote_addr={} server_name={}",
                destination.addr(),
                destination.host()
            );
            let connecting = endpoint
                .connect(destination.addr, &destination.host)
                .inspect_err(|e| {
                    error!(
                        "Unable to connect to remote_addr={} server_name={} {e}",
                        destination.addr, destination.host
                    );
                })?;
            let connection = connecting.await.inspect_err(|e| {
                error!(
                    "Unable to initialize connection to remote_addr={} server_name={} {e}",
                    destination.addr, destination.host
                );
            })?;
            let connection = Arc::new(connection);
            *state = SocketState::Connected(connection.clone());
            Ok((connection, true))
        }
        SocketState::Connected(connection) => {
            debug!(
                "Using existing connection local_addr={bound_addr} remote_addr={} server_name={}",
                destination.addr(),
                destination.host()
            );
            Ok((connection.clone(), false))
        }
    }
}
