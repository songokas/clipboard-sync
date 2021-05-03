use futures::future::try_join_all;
use std::io;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::select;
use tokio::time::{sleep, timeout, Duration};

use crate::defaults::{MAX_UDP_BUFFER, MAX_UDP_PAYLOAD};
use crate::errors::ConnectionError;
use crate::protocols::tcp::{obtain_client_socket, obtain_server_socket, receive_stream};
use crate::socket::{receive_from_timeout, Timeout};

pub async fn receive_data(
    socket: &UdpSocket,
    max_len: usize,
    timeout_callback: impl Timeout,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let mut buffer = [0; MAX_UDP_BUFFER];

    let callback = |d: Duration| timeout_callback(d);

    let (read, addr) = receive_from_timeout(socket, &mut buffer, callback).await?;

    if read == 1 && buffer[0] == 49 {
        let data = tokio::select! {
            result = listen_receive_stream(socket.local_addr()?, max_len, callback) => result,
            // result = connect_receive_stream(socket.local_addr()?, addr, max_len, callback) => result,
        };

        return data;
    }
    let size = if read > max_len { max_len } else { read };
    return Ok((buffer[..size].to_vec(), addr));
}

pub async fn send_data(
    socket: UdpSocket,
    data: Vec<u8>,
    destination: &SocketAddr,
) -> Result<usize, ConnectionError>
{
    if data.len() > MAX_UDP_PAYLOAD {
        let sent = socket.send(b"1").await?;
        sleep(Duration::from_millis(100)).await;
        let n = tokio::select! {
            // result = listen_send_stream(socket.local_addr()?, &data) => result,
            result = connect_send_stream(socket.local_addr()?, &data, destination.clone()) => result,
        };
        return Ok(n?);
    }
    return Ok(socket.send(&data).await?);
}

pub async fn obtain_socket(
    local_address: &SocketAddr,
    remote_addr: &SocketAddr,
) -> Result<UdpSocket, ConnectionError>
{
    let sock = UdpSocket::bind(local_address).await.map_err(|e| {
        ConnectionError::FailedToConnect(format!(
            "Unable to bind local address {} {}",
            local_address, e
        ))
    })?;
    sock.connect(remote_addr).await.map_err(|e| {
        ConnectionError::FailedToConnect(format!(
            "Unable to connect local address {} to remote address {} {}",
            local_address, remote_addr, e
        ))
    })?;

    if remote_addr.ip().is_multicast() {
        sock.set_multicast_loop_v4(false).unwrap_or(());
        sock.set_multicast_loop_v6(false).unwrap_or(());
    }
    return Ok(sock);
}

async fn listen_receive_stream(
    local_addr: SocketAddr,
    max_len: usize,
    timeout_callback: impl Timeout,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let listener = obtain_server_socket(local_addr)?;
    let (stream, addr) = match timeout(Duration::from_millis(4000), listener.accept()).await {
        Ok(v) => v?,
        Err(_) => return Err(ConnectionError::Timeout(Duration::from_millis(4000))),
    };
    return receive_stream(stream, addr, max_len, timeout_callback).await;
}

async fn connect_receive_stream(
    local_addr: SocketAddr,
    destination: SocketAddr,
    max_len: usize,
    timeout: impl Timeout,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let socket = obtain_client_socket(SocketAddr::new(local_addr.ip(), 0))?;
    let stream = socket.connect(destination).await?;
    return receive_stream(stream, destination, max_len, timeout).await;
}

async fn listen_send_stream(local_addr: SocketAddr, data: &[u8]) -> Result<usize, ConnectionError>
{
    let listener = obtain_server_socket(local_addr)?;
    let (mut stream, addr) = match timeout(Duration::from_millis(4000), listener.accept()).await {
        Ok(v) => v?,
        Err(_) => return Err(ConnectionError::Timeout(Duration::from_millis(4000))),
    };
    let res = stream.write_all(&data).await?;
    stream.shutdown().await?;
    return Ok(data.len());
}

async fn connect_send_stream(
    local_addr: SocketAddr,
    data: &[u8],
    destination: SocketAddr,
) -> Result<usize, ConnectionError>
{
    let socket = obtain_client_socket(SocketAddr::new(local_addr.ip(), 0))?;
    let mut stream = socket.connect(destination).await?;
    let res = stream.write_all(&data).await?;
    stream.shutdown().await?;
    return Ok(data.len());
}

#[cfg(test)]
mod basictest
{
    use super::*;
    use crate::assert_error_type;
    use crate::encryption::random;
    use futures::try_join;

    #[tokio::test]
    async fn test_send_receive()
    {
        let local_server: SocketAddr = "127.0.0.1:39833".parse().unwrap();
        let local_client: SocketAddr = "127.0.0.1:39834".parse().unwrap();
        let server_sock = UdpSocket::bind(local_server).await.unwrap();
        let client_sock = UdpSocket::bind(local_client).await.unwrap();
        client_sock.connect(local_server).await.unwrap();
        let data_sent = b"test1".to_vec();

        let data_len_sent = send_data(client_sock, data_sent.clone(), &local_server)
            .await
            .unwrap();

        let (data_received, addr) = receive_data(&server_sock, 10, |d: Duration| {
            d > Duration::from_millis(2000)
        })
        .await
        .unwrap();

        assert_eq!(local_client, addr);
        assert_eq!(data_len_sent, 5);
        assert_eq!(data_sent, data_received);
    }

    #[tokio::test]
    async fn test_max_data()
    {
        let local_server: SocketAddr = "127.0.0.1:39835".parse().unwrap();
        let local_client: SocketAddr = "127.0.0.1:39836".parse().unwrap();
        let server_sock = UdpSocket::bind(local_server).await.unwrap();
        let client_sock = UdpSocket::bind(local_client).await.unwrap();
        client_sock.connect(local_server).await.unwrap();
        let data_sent = b"test1".to_vec();

        let data_len_sent = send_data(client_sock, data_sent.clone(), &local_server)
            .await
            .unwrap();

        let (data_received, addr) = receive_data(&server_sock, 2, |d: Duration| {
            d > Duration::from_millis(2000)
        })
        .await
        .unwrap();

        assert_eq!(local_client, addr);
        assert_eq!(data_len_sent, 5);
        assert_eq!(b"te", data_received.as_slice());
    }

    #[tokio::test]
    async fn test_send_large_data()
    {
        let local_server: SocketAddr = "127.0.0.1:35837".parse().unwrap();
        let local_client: SocketAddr = "127.0.0.1:35838".parse().unwrap();
        let mut server_sock = UdpSocket::bind(local_server).await.unwrap();
        let client_sock = UdpSocket::bind(local_client).await.unwrap();
        client_sock.connect(local_server).await.unwrap();
        let size = 10 * 1024 * 10;
        let data_sent = random(size);
        let max_len = size;
        let for_sending = data_sent.clone();

        let res = try_join!(
            tokio::spawn(async move {
                receive_data(&mut server_sock, max_len, |d: Duration| {
                    d > Duration::from_millis(2000)
                })
                .await
            }),
            tokio::spawn(async move { send_data(client_sock, for_sending, &local_server).await }),
        )
        .unwrap();

        let (data_received, addr) = res.0.unwrap();
        let data_len_sent = res.1.unwrap();

        // assert_eq!(local_client, addr);
        assert_eq!(data_len_sent, data_sent.len());
        assert_eq!(data_sent, data_received);
    }

    #[tokio::test]
    async fn test_timeout()
    {
        let local_server: SocketAddr = "127.0.0.1:39837".parse().unwrap();
        let server_sock = UdpSocket::bind(local_server).await.unwrap();
        let result = receive_data(&server_sock, 10, |_: Duration| true).await;
        assert_error_type!(result, ConnectionError::IoError(_));
    }
}
