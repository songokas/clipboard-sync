use crate::errors::ConnectionError;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub async fn receive_data_basic(
    socket: &UdpSocket,
    max_len: usize,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let mut data = vec![0; max_len];
    let (_, addr) = socket.recv_from(&mut data).await?;
    return Ok((data, addr));
}

pub async fn send_data_basic(socket: UdpSocket, data: Vec<u8>) -> Result<usize, ConnectionError>
{
    return Ok(socket.send(&data).await?);
}
