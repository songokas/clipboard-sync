use crate::defaults::MAX_UDP_BUFFER;
use crate::errors::ConnectionError;
use crate::socket::receive_from_timeout;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::Duration;

pub async fn receive_data_basic(
    socket: &UdpSocket,
    max_len: usize,
    timeout: impl Fn(Duration) -> bool,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let mut buffer = [0; MAX_UDP_BUFFER];

    let (read, addr) = receive_from_timeout(socket, &mut buffer, timeout).await?;

    let size = if read > max_len { max_len } else { read };
    return Ok((buffer[..size].to_vec(), addr));
}

pub async fn send_data_basic(socket: UdpSocket, data: Vec<u8>) -> Result<usize, ConnectionError>
{
    return Ok(socket.send(&data).await?);
}

#[cfg(test)]
mod basictest
{
    use super::*;
    use crate::assert_error_type;

    #[tokio::test]
    async fn test_send_receive()
    {
        let local_server: SocketAddr = "127.0.0.1:39833".parse().unwrap();
        let local_client: SocketAddr = "127.0.0.1:39834".parse().unwrap();
        let server_sock = UdpSocket::bind(local_server).await.unwrap();
        let client_sock = UdpSocket::bind(local_client).await.unwrap();
        client_sock.connect(local_server).await.unwrap();
        let data_sent = b"test1".to_vec();

        let data_len_sent = send_data_basic(client_sock, data_sent.clone())
            .await
            .unwrap();

        let (data_received, addr) = receive_data_basic(&server_sock, 10, |d: Duration| {
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

        let data_len_sent = send_data_basic(client_sock, data_sent.clone())
            .await
            .unwrap();

        let (data_received, addr) = receive_data_basic(&server_sock, 2, |d: Duration| {
            d > Duration::from_millis(2000)
        })
        .await
        .unwrap();

        assert_eq!(local_client, addr);
        assert_eq!(data_len_sent, 5);
        assert_eq!(b"te", data_received.as_slice());
    }

    #[tokio::test]
    async fn test_timeout()
    {
        let local_server: SocketAddr = "127.0.0.1:39837".parse().unwrap();
        let server_sock = UdpSocket::bind(local_server).await.unwrap();
        let result = receive_data_basic(&server_sock, 10, |_: Duration| true).await;
        assert_error_type!(result, ConnectionError::IoError(_));
    }
}
