use indexmap::IndexSet;
use log::debug;
use log::error;
use log::info;
use log::trace;
use log::warn;
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::defaults::ExecutorResult;
use crate::defaults::INIDICATION_SIZE;
use crate::defaults::{DATA_TIMEOUT, MAX_UDP_BUFFER};
use crate::encryptor::MessageDecryptor;
use crate::identity::IdentityVerifier;
use crate::multicast::join_multicast;
use crate::pools::udp_pool::UdpSocketPool;
use crate::protocol::Protocol;

use crate::protocol_readers::process_receive_stream_result;
use crate::protocol_readers::StreamReceiveError;
use crate::protocols::basic::obtain_server_socket;
use crate::protocols::tcp::tcp_receive;
use crate::protocols::ProtocolReadMessage;

use crate::socket::split_into_messages;

pub async fn create_basic_reader<V>(
    sender: Sender<ProtocolReadMessage>,
    verifier: V,
    udp_pool: UdpSocketPool,
    local_addr: SocketAddr,
    multicast_ips: IndexSet<IpAddr>,
    max_len: usize,
    cancel: CancellationToken,
) -> ExecutorResult
where
    V: MessageDecryptor + IdentityVerifier,
{
    let socket = Arc::new(obtain_server_socket(local_addr).await?);

    for ip in multicast_ips.into_iter().filter(|i| i.is_multicast()) {
        join_multicast(&socket, ip, local_addr.ip())?;
    }

    udp_pool.add(socket.clone()).await;

    basic_reader_executor(sender, verifier, socket, max_len, cancel).await
}

async fn basic_reader_executor<V>(
    sender: Sender<ProtocolReadMessage>,
    verifier: V,
    socket: Arc<UdpSocket>,
    max_len: usize,
    cancel: CancellationToken,
) -> ExecutorResult
where
    V: IdentityVerifier + MessageDecryptor,
{
    let mut handles = JoinSet::new();
    let mut buffer = [0; MAX_UDP_BUFFER];
    let mut success_count = 0;
    let bound_addr = socket.local_addr().expect("Bound address");

    info!(
        "Listening on local_addr={bound_addr} protocol={}",
        Protocol::Basic
    );

    let mut tcp_locks: HashMap<(SocketAddr, SocketAddr), Arc<Mutex<bool>>> = HashMap::new();

    loop {
        select! {
            _ = cancel.cancelled() => {
                debug!("Reader cancelled");
                break;
            }
            // we expect data to be read in full for udp
            result = socket.recv_from(&mut buffer) => {
                let (size_read, remote_addr) = match result {
                    Ok((size_read, remote_addr)) => {
                        if size_read > max_len {
                            warn!("Received more data {size_read} than expected {max_len} remote_addr={remote_addr}");
                            continue;
                        }
                        trace!("Received data_size={size_read} remote_addr={remote_addr}");
                        (size_read, remote_addr)
                    },
                    Err(e) => {
                        error!("Socket receive error {e}");
                        continue;
                    }
                };

                let Some(_) = verifier.verify(remote_addr.into()) else {
                    debug!("Peer {remote_addr} is not allowed");
                    continue;
                };
                if size_read == 1 && buffer[0] == 49 {
                    let socket = tcp_locks.entry((bound_addr, remote_addr)).or_default().clone();
                    handles.spawn(async move {
                        // we can only receive once per local remote socket
                        let _value = socket.lock().await;
                        let (data, remote_addr) = tcp_receive(bound_addr, remote_addr, max_len, DATA_TIMEOUT).await
                            .map_err(|error| StreamReceiveError { error, remote_addr })?;
                        Ok(((), data, remote_addr))
                    });
                } else {
                    if size_read < INIDICATION_SIZE {
                        warn!("Received less bytes {size_read} than expected {INIDICATION_SIZE}");
                        continue;
                    }
                    let messages = split_into_messages(&buffer[..size_read]);
                    if messages.is_empty() {
                        warn!("Unknown data received remote_addr={remote_addr} size_read={size_read}");
                    }
                    for message in messages {
                        let result = Ok(((), message, remote_addr));
                        let Err(None) = process_receive_stream_result(Ok(result), &verifier, &sender).await.map(|_| success_count+=1 ) else {
                            break;
                        };
                    }
                }
            }
            Some(stream_finished) = handles.join_next(), if !handles.is_empty() => {
                if let Err(None) = process_receive_stream_result(stream_finished, &verifier, &sender).await.map(|_| success_count+=1 ) {
                    debug!("Reader cancelled");
                    break;
                };
            }
        }
        tcp_locks.retain(|_, v| Arc::strong_count(v) > 1);
    }
    Ok(("basic reader", success_count))
}
