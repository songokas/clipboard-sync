use log::debug;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::select;
use tokio::time::{timeout, Duration};

use crate::defaults::{CONNECTION_TIMEOUT, MAX_UDP_BUFFER, MAX_UDP_PAYLOAD};
use crate::errors::ConnectionError;
use crate::protocols::tcp::{obtain_client_socket, obtain_server_socket, receive_stream};
use crate::socket::{receive_from_timeout, remove_ipv4_mapping};

pub async fn receive_data(
    socket: Arc<UdpSocket>,
    max_len: usize,
    timeout_callback: impl Fn(Duration) -> bool,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError> {
    let mut buffer = [0; MAX_UDP_BUFFER];

    let callback = |d: Duration| timeout_callback(d);

    let (read, addr) = receive_from_timeout(&socket, &mut buffer, callback).await?;

    if read == 1 && buffer[0] == 49 {
        let duration = Duration::from_millis(CONNECTION_TIMEOUT);
        let callback = |d: Duration| d > duration || timeout_callback(d);
        let local_addr = socket.local_addr()?;
        let destination = remove_ipv4_mapping(&addr);

        debug!(
            "tcp receive local {} to destination {}",
            local_addr, destination
        );

        let stream = select! {
            biased;
            Ok(stream) = listen_stream(local_addr, callback) => Ok(stream),
            Ok(stream) = connect_stream(local_addr, destination) => Ok(stream),
            else => Err(ConnectionError::Timeout("basic receive".to_owned(), duration)),
        }?;
        return receive_stream(stream, addr, max_len, callback).await;
    }

    if read > max_len {
        return Err(ConnectionError::LimitReached {
            received: read,
            max_len,
        });
    }
    return Ok((buffer[..read].to_vec(), addr));
}

pub async fn send_data(
    socket: Arc<UdpSocket>,
    data: Vec<u8>,
    destination: &SocketAddr,
    timeout_callback: impl Fn(Duration) -> bool,
) -> Result<usize, ConnectionError> {
    if data.len() > MAX_UDP_PAYLOAD {
        socket.send_to(b"1", destination).await?;

        let duration = Duration::from_millis(CONNECTION_TIMEOUT);
        let callback = |d: Duration| d > duration || timeout_callback(d);
        let local_addr = socket.local_addr()?;

        debug!(
            "tcp send local {} to destination {}",
            local_addr, destination
        );

        let mut stream = select! {
            biased;
            Ok(stream) = connect_stream(local_addr, destination.clone()) => Ok(stream),
            Ok(stream) = listen_stream(local_addr, callback) => Ok(stream),
            else => Err(ConnectionError::Timeout("basic send".to_owned(), duration)),
        }?;

        stream.write_all(&data).await?;
        stream.shutdown().await?;
        return Ok(data.len());
    }
    return Ok(socket.send_to(&data, destination).await?);
}

async fn listen_stream(
    local_addr: SocketAddr,
    timeout_callback: impl Fn(Duration) -> bool,
) -> Result<TcpStream, ConnectionError> {
    let listener = obtain_server_socket(local_addr)?;
    let now = Instant::now();
    while !timeout_callback(now.elapsed()) {
        let (stream, _) = match timeout(Duration::from_millis(100), listener.accept()).await {
            Ok(v) => v?,
            Err(_) => continue,
        };
        return Ok(stream);
    }
    return Err(ConnectionError::Timeout(
        "basic listen stream".to_owned(),
        now.elapsed(),
    ));
}

async fn connect_stream(
    local_addr: SocketAddr,
    destination: SocketAddr,
) -> Result<TcpStream, ConnectionError> {
    let socket = obtain_client_socket(local_addr)?;
    let stream = socket.connect(destination).await?;
    return Ok(stream);
}

#[cfg(test)]
mod basictest {
    use super::*;
    use crate::assert_error_type;
    use crate::encryption::random;
    use futures::try_join;

    async fn send_receive(size: usize, max_len: usize) {
        let local_server: SocketAddr = "127.0.0.1:35837".parse().unwrap();
        let local_client: SocketAddr = "127.0.0.1:35838".parse().unwrap();
        let server_sock = Arc::new(UdpSocket::bind(local_server).await.unwrap());
        let client_sock = Arc::new(UdpSocket::bind(local_client).await.unwrap());
        client_sock.connect(local_server).await.unwrap();

        let data_sent = random(size);
        let for_sending = data_sent.clone();

        let res = try_join!(
            tokio::spawn(async move {
                receive_data(server_sock, max_len, |d: Duration| {
                    d > Duration::from_millis(2000)
                })
                .await
            }),
            tokio::spawn(async move {
                send_data(client_sock, for_sending, &local_server, |d: Duration| {
                    d > Duration::from_millis(2000)
                })
                .await
            }),
        )
        .unwrap();

        if size > max_len {
            assert_error_type!(res.0, ConnectionError::LimitReached { .. });
        } else {
            let (data_received, _) = res.0.unwrap();
            let data_len_sent = res.1.unwrap();
            assert_eq!(data_len_sent, data_sent.len());
            assert_eq!(data_sent, data_received);
        }
    }

    #[tokio::test]
    async fn test_data() {
        send_receive(5, 10).await;
        send_receive(16 * 1024 * 10, 16 * 1024 * 10).await;
        send_receive(10, 5).await;
        send_receive(16 * 1024 * 10, 10).await;
    }

    #[tokio::test]
    async fn test_timeout() {
        let local_server: SocketAddr = "127.0.0.1:39837".parse().unwrap();
        let server_sock = Arc::new(UdpSocket::bind(local_server).await.unwrap());
        let result = receive_data(server_sock, 10, |_: Duration| true).await;
        assert_error_type!(result, ConnectionError::IoError(_));
    }
}
