use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::{timeout, Duration};

use crate::defaults::DATA_TIMEOUT;
use crate::errors::ConnectionError;
use crate::fragmenter::RelayEncryptor;
use crate::identity::{Identity, IdentityVerifier};
use crate::stream::{receive_stream, send_stream, StreamPool};

pub async fn receive_data(
    listener: (&TcpListener, Arc<StreamPool>),
    verifier: &impl IdentityVerifier,
    max_len: usize,
    timeout_callback: impl Fn(Duration) -> bool,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let (socket, pool) = listener;
    let now = Instant::now();
    let timeout_with_duration =
        |d: Duration| -> bool { d > Duration::from_millis(DATA_TIMEOUT) || timeout_callback(d) };
    let current_sockets: HashSet<SocketAddr> = HashSet::new();
    while !timeout_callback(now.elapsed()) {
        let (peer_addr, stream) = match timeout(Duration::from_millis(100), socket.accept()).await {
            Ok(v) => {
                let (s, a) = v?;
                // debug!("Tcp received new connection {}", a);
                (a, Arc::new(s))
            }
            Err(_) => match pool.get_stream_with_data(&current_sockets).await {
                Some(s) => s,
                None => continue,
            },
        };
        verifier
            .verify(&Identity::from(peer_addr))
            .ok_or(ConnectionError::InvalidSource(peer_addr))?;

        return match receive_stream(stream.clone(), max_len, timeout_with_duration).await {
            Ok(d) if !d.is_empty() => {
                pool.add(stream).await;
                Ok((d, peer_addr))
            }
            Ok(d) => {
                pool.remove(&peer_addr).await;
                Ok((d, peer_addr))
            }
            Err(e) => {
                pool.remove(&peer_addr).await;
                Err(e)
            }
        };
    }
    Err(ConnectionError::Timeout(
        "tcp receive".to_owned(),
        now.elapsed(),
    ))
}

pub async fn send_data(
    socket: TcpSocket,
    encryptor: &impl RelayEncryptor,
    data: Vec<u8>,
    destination: &SocketAddr,
    timeout_callback: impl Fn(Duration) -> bool,
) -> Result<usize, ConnectionError>
{
    let mut stream = socket.connect(*destination).await?;
    let total_sent = send_stream(&stream, encryptor, data, timeout_callback).await?;
    stream.shutdown().await?;
    Ok(total_sent)
}

pub fn obtain_client_socket(local_address: SocketAddr) -> Result<TcpSocket, ConnectionError>
{
    let socket = if local_address.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    socket.set_reuseaddr(true)?;
    #[cfg(target_os = "linux")]
    socket.set_reuseport(true)?;
    socket
        .bind(local_address)
        .map_err(|e| ConnectionError::BindError(local_address, e))?;
    Ok(socket)
}

pub fn obtain_server_socket(local_address: SocketAddr) -> Result<TcpListener, ConnectionError>
{
    let socket = if local_address.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    socket.set_reuseaddr(true)?;
    #[cfg(target_os = "linux")]
    socket.set_reuseport(true)?;

    socket
        .bind(local_address)
        .map_err(|e| ConnectionError::BindError(local_address, e))?;

    let listener = socket.listen(1024)?;
    Ok(listener)
}

pub async fn connect_stream(
    local_addr: SocketAddr,
    destination: SocketAddr,
) -> Result<TcpStream, ConnectionError>
{
    let socket = obtain_client_socket(local_addr)?;
    let stream = socket.connect(destination).await?;
    Ok(stream)
}

#[cfg(test)]
mod tcptest
{
    use super::*;
    use crate::assert_error_type;
    use crate::defaults::INIDICATION_SIZE;
    use crate::encryption::random;
    use crate::fragmenter::GroupsEncryptor;
    use crate::fragmenter::NoRelayEncryptor;
    use crate::message::Group;
    use futures::try_join;
    use indexmap::indexmap;

    async fn send_receive(size: usize, max_len: usize)
    {
        let client_str = "127.0.0.1:38330";
        let local_server: SocketAddr = "127.0.0.1:38329".parse().unwrap();
        let local_client: SocketAddr = client_str.parse().unwrap();
        let server_sock = obtain_server_socket(local_server).unwrap();
        let client_sock = obtain_client_socket(local_client).unwrap();
        let stream_pool = Arc::new(StreamPool::default());
        let encryptor = NoRelayEncryptor {};

        let data_sent = random(size);
        let for_sending = data_sent.clone();

        let group = Group::from_addr("test1", client_str, client_str);
        let groups = indexmap! {group.name.clone() => group.clone()};
        let enc_r = GroupsEncryptor::new(groups);

        let res = try_join!(
            tokio::spawn(async move {
                receive_data(
                    (&server_sock, stream_pool.clone()),
                    &enc_r,
                    max_len,
                    |d: Duration| d > Duration::from_millis(8000),
                )
                .await
            }),
            tokio::spawn(async move {
                send_data(
                    client_sock,
                    &encryptor,
                    for_sending,
                    &local_server,
                    |d: Duration| d > Duration::from_millis(8000),
                )
                .await
            }),
        )
        .unwrap();

        if size > max_len {
            assert_error_type!(res.0, ConnectionError::LimitReached { .. });
        } else {
            let (data_received, addr) = res.0.unwrap();
            let data_len_sent = res.1.unwrap();
            assert_eq!(local_client, addr);
            assert_eq!(data_len_sent, size + INIDICATION_SIZE);
            assert_eq!(data_sent, data_received);
        }
    }

    #[tokio::test]
    async fn test_data()
    {
        send_receive(5, 10).await;
        send_receive(16 * 1024 * 10, 16 * 1024 * 10).await;
        send_receive(10, 5).await;
    }

    #[tokio::test]
    async fn test_timeout()
    {
        let client_str = "127.0.0.1:39837";
        let group = Group::from_addr("test1", client_str, client_str);
        let groups = indexmap! {group.name.clone() => group.clone()};
        let enc_r = GroupsEncryptor::new(groups);
        let stream_pool = Arc::new(StreamPool::default());

        let local_server: SocketAddr = client_str.parse().unwrap();
        let server_sock = obtain_server_socket(local_server).unwrap();
        let result =
            receive_data((&server_sock, stream_pool), &enc_r, 10, |_: Duration| true).await;
        assert_error_type!(result, ConnectionError::Timeout(..));
    }
}
