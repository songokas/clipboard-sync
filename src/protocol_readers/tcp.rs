use core::net::IpAddr;
use core::ops::DerefMut;
use indexmap::IndexSet;
use log::{debug, error, info};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::select;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::defaults::{ExecutorResult, WAIT_TIMEOUT};
use crate::encryptor::MessageDecryptor;
use crate::identity::IdentityVerifier;
use crate::multicast::{advertise_service, join_multicast};
use crate::pools::tcp_stream_pool::TcpStreamPool;
use crate::protocol::Protocol;
use crate::protocol_readers::{process_receive_stream_result, StreamReceiveError};
use crate::protocols::tcp::obtain_server_socket;
use crate::protocols::ProtocolReadMessage;
use crate::stream::{receive_stream, ReadStream};

pub async fn create_tcp_reader<T>(
    sender: Sender<ProtocolReadMessage>,
    verifier: T,
    tcp_stream_pool: TcpStreamPool,
    multicast_ips: IndexSet<IpAddr>,
    local_addr: SocketAddr,
    max_len: usize,
    cancel: CancellationToken,
) -> ExecutorResult
where
    T: MessageDecryptor + IdentityVerifier,
{
    let listener = obtain_server_socket(local_addr)?;
    let bound_addr = listener.local_addr().expect("Bound address");

    let multicast_socket = if !multicast_ips.is_empty() {
        let multicast_socket = UdpSocket::bind(bound_addr).await?;
        for ip in multicast_ips.into_iter().filter(|i| i.is_multicast()) {
            join_multicast(&multicast_socket, ip, bound_addr.ip())?;
        }
        multicast_socket.into()
    } else {
        None
    };
    tcp_reader_executor(
        sender,
        verifier,
        tcp_stream_pool,
        listener,
        multicast_socket,
        max_len,
        cancel,
    )
    .await
}

async fn tcp_reader_executor<T>(
    sender: Sender<ProtocolReadMessage>,
    verifier: T,
    tcp_stream_pool: TcpStreamPool,
    listener: TcpListener,
    multicast_socket: Option<UdpSocket>,
    max_len: usize,
    cancel: CancellationToken,
) -> ExecutorResult
where
    T: IdentityVerifier + MessageDecryptor,
{
    let mut stream_handles: JoinSet<Result<_, StreamReceiveError>> = JoinSet::new();
    let mut success_count = 0;
    let bound_addr = listener.local_addr().expect("Bound address");
    let server_name = None;

    info!(
        "Listening on local_addr={bound_addr} protocol={} multicast_addr={}",
        Protocol::Tcp,
        multicast_socket
            .as_ref()
            .map(|l| l.local_addr().expect("Multicast local addr").to_string())
            .unwrap_or_else(|| "None".to_string())
    );

    loop {
        select! {
            _ = cancel.cancelled() => {
                debug!("Cancel reader");
                break;
            }
            (stream, remote_addr) = tcp_stream_pool.wait_for_new_read_stream(bound_addr) => {
                stream_handles.spawn(wait_for_stream(stream, remote_addr, max_len));
            }
            Err(e) = async { advertise_service(multicast_socket.as_ref().expect("Multicast socket"), Protocol::Tcp, bound_addr.port(), server_name.clone()).await }, if multicast_socket.is_some() => {
                debug!("Multicast failed {e}");
            }
            // new connection
            new_connection = listener.accept() => {
                accept_new_connection(new_connection, &verifier, &tcp_stream_pool, bound_addr).await;
            }
            Some(stream_finished) = stream_handles.join_next(), if !stream_handles.is_empty() => {
                match process_receive_stream_result(stream_finished, &verifier, &sender).await {
                    Ok((stream, remote_addr)) => {
                        success_count += 1;
                        stream_handles.spawn(wait_for_stream(stream, remote_addr, max_len));
                    }
                    Err(Some(remote_addr)) => {
                        tcp_stream_pool.remove(bound_addr, remote_addr).await;
                    }
                    Err(None) => {
                        debug!("Reader, no clients listening");
                        break;
                    }
                }
            }
        }
    }
    Ok(("tcp reader", success_count))
}

pub async fn wait_for_stream<S: ReadStream>(
    stream: Arc<Mutex<S>>,
    remote_addr: SocketAddr,
    max_len: usize,
) -> Result<(Arc<Mutex<S>>, Vec<u8>, SocketAddr), StreamReceiveError> {
    let mut s = stream.lock().await;

    debug!("Waiting for stream from remote_addr={remote_addr}");

    let data = receive_stream(s.deref_mut(), max_len, WAIT_TIMEOUT)
        .await
        .map_err(|error| StreamReceiveError { error, remote_addr })?;
    drop(s);
    Ok((stream, data, remote_addr))
}

async fn accept_new_connection<T>(
    new_connection: std::io::Result<(TcpStream, SocketAddr)>,
    verifier: &T,
    tcp_stream_pool: &TcpStreamPool,
    bound_addr: SocketAddr,
) where
    T: IdentityVerifier,
{
    match new_connection {
        Ok((stream, peer_addr)) => {
            let Some(_) = verifier.verify(peer_addr.into()) else {
                debug!("Peer {peer_addr} is not allowed");
                return;
            };

            debug!("New connection remote_addr={}", peer_addr);

            let (reader, writer) = stream.into_split();
            if let Err(e) = tcp_stream_pool.add_writer(bound_addr, writer).await {
                error!("Unable to add stream: {e}");
                return;
            }

            if let Err(e) = tcp_stream_pool.add_reader(bound_addr, reader).await {
                error!("Unable to add stream: {e}");
            }
        }
        Err(e) => {
            error!("Tcp accept error {e}");
        }
    }
}
