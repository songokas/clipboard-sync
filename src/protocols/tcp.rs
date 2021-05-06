use crate::defaults::CONNECTION_TIMEOUT;
use crate::errors::ConnectionError;
// use crate::socket::Timeout;
use std::io;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::{timeout, Duration};

pub async fn receive_data(
    socket: &TcpListener,
    max_len: usize,
    timeout_callback: impl Fn(Duration) -> bool,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let now = Instant::now();
    while !timeout_callback(now.elapsed()) {
        let (stream, sock_addr) = match timeout(Duration::from_millis(100), socket.accept()).await {
            Ok(v) => v?,
            Err(_) => continue,
        };
        let timeout_with_duration = |d: Duration| -> bool {
            return d > Duration::from_millis(CONNECTION_TIMEOUT) && timeout_callback(d);
        };
        return receive_stream(stream, sock_addr, max_len, timeout_with_duration).await;
    }
    return Err(ConnectionError::Timeout(
        "tcp receive".to_owned(),
        now.elapsed(),
    ));
}

pub async fn receive_stream(
    stream: TcpStream,
    addr: SocketAddr,
    max_len: usize,
    timeout: impl Fn(Duration) -> bool,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let mut buffer = [0; 10000];
    let mut data = Vec::new();
    let now = Instant::now();
    while !timeout(now.elapsed()) {
        stream.readable().await?;

        match stream.try_read(&mut buffer) {
            Ok(0) => {
                return Ok((data, addr));
            }
            Ok(n) => {
                let mut data_read = buffer[0..n].to_vec();
                if (data.len() + data_read.len()) > max_len {
                    return Err(ConnectionError::LimitReached {
                        received: data.len() + data_read.len(),
                        max_len,
                    });
                }
                data.append(&mut data_read);
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
    return Err(ConnectionError::Timeout(
        "tcp receive stream".to_owned(),
        now.elapsed(),
    ));
}

pub async fn send_data(
    socket: TcpSocket,
    data: Vec<u8>,
    destination: &SocketAddr,
) -> Result<usize, ConnectionError>
{
    let mut stream = socket.connect(destination.clone()).await?;
    stream.write_all(&data).await?;
    stream.shutdown().await?;
    return Ok(data.len());
}

pub fn obtain_client_socket(local_address: SocketAddr) -> Result<TcpSocket, ConnectionError>
{
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    #[cfg(target_os = "linux")]
    socket.set_reuseport(true)?;
    socket.bind(local_address)?;
    return Ok(socket);
}

pub fn obtain_server_socket(local_address: SocketAddr) -> Result<TcpListener, ConnectionError>
{
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    #[cfg(target_os = "linux")]
    socket.set_reuseport(true)?;
    socket.bind(local_address)?;
    let listener = socket.listen(1024)?;
    return Ok(listener);
}

#[cfg(test)]
mod tcptest
{
    use super::*;
    use crate::assert_error_type;
    use crate::encryption::random;
    use futures::try_join;

    async fn send_receive(size: usize, max_len: usize)
    {
        let local_server: SocketAddr = "127.0.0.1:38329".parse().unwrap();
        let local_client: SocketAddr = "127.0.0.1:38330".parse().unwrap();
        let server_sock = obtain_server_socket(local_server).unwrap();
        let client_sock = obtain_client_socket(local_client).unwrap();

        let data_sent = random(size);
        let for_sending = data_sent.clone();

        let res = try_join!(
            tokio::spawn(async move {
                receive_data(&server_sock, max_len, |d: Duration| {
                    d > Duration::from_millis(8000)
                })
                .await
            }),
            tokio::spawn(async move { send_data(client_sock, for_sending, &local_server).await }),
        )
        .unwrap();

        if size > max_len {
            assert_error_type!(res.0, ConnectionError::LimitReached { .. });
        } else {
            let (data_received, addr) = res.0.unwrap();
            let data_len_sent = res.1.unwrap();
            assert_eq!(local_client, addr);
            assert_eq!(data_len_sent, size);
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
        let local_server: SocketAddr = "127.0.0.1:39837".parse().unwrap();
        let server_sock = obtain_server_socket(local_server).unwrap();
        let result = receive_data(&server_sock, 10, |_: Duration| true).await;
        assert_error_type!(result, ConnectionError::Timeout(..));
    }
}
