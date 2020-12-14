use crate::errors::ConnectionError;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub async fn receive_data_basic(
    socket: &UdpSocket,
    max_len: usize,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let mut data = vec![0; max_len];
    let (read, addr) = socket.recv_from(&mut data).await?;
    data.truncate(read);
    return Ok((data, addr));
}

pub async fn send_data_basic(socket: UdpSocket, data: Vec<u8>) -> Result<usize, ConnectionError>
{
    return Ok(socket.send(&data).await?);
}

#[cfg(test)]
mod basictest
{
    use super::*;

    #[tokio::test]
    async fn test_send_receive()
    {
        let local_server: SocketAddr = "127.0.0.1:9932".parse().unwrap();
        let local_client: SocketAddr = "127.0.0.1:9933".parse().unwrap();
        let server_sock = UdpSocket::bind(local_server).await.unwrap();
        let client_sock = UdpSocket::bind(local_client).await.unwrap();
        client_sock.connect(local_server).await.unwrap();
        let data_sent = b"test1".to_vec();
        let data_len_sent = send_data_basic(client_sock, data_sent.clone()).await.unwrap();
        let (data_received, addr) = receive_data_basic(&server_sock, 10).await.unwrap(); 

        assert_eq!(local_client, addr);
        assert_eq!(data_len_sent, 5);
        assert_eq!(data_sent, data_received);
    }
}