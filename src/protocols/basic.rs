use futures::future::try_join_all;
use std::io;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

use crate::defaults::MAX_UDP_BUFFER;
use crate::errors::ConnectionError;
use crate::socket::{receive_from_timeout, Timeout};

pub async fn receive_data(
    socket: &UdpSocket,
    max_len: usize,
    timeout_callback: impl Timeout,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let mut buffer = [0; MAX_UDP_BUFFER];

    let (read, addr) = receive_from_timeout(socket, &mut buffer, timeout_callback).await?;
    // large data
    // if read == 1 && buffer[0] == 0 {
    let stream = TcpStream::connect("127.0.0.1:9008").await?;
    let mut data = Vec::new();
    let now = Instant::now();
    while now.elapsed() < Duration::from_millis(2000) {
        println!("readable called 1");

        stream.readable().await?;

        println!("readable called 2");

        match stream.try_read(&mut buffer) {
            Ok(0) => {
                println!("0 called");
                return Ok((data, addr));
            }
            Ok(n) => {
                println!("received called");
                let mut data_read = buffer[0..n].to_vec();
                if (data.len() + data_read.len()) > max_len {
                    return Err(ConnectionError::LimitReached(format!(
                        "Connection limit reached: expected {} received {}",
                        max_len,
                        data.len() + data_read.len()
                    )));
                }
                data.append(&mut data_read);
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                println!("WouldBlock called");
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    // return read_stream(stream, max_len, timeout);
    // }

    let size = if read > max_len { max_len } else { read };
    return Ok((buffer[..size].to_vec(), addr));
}

// fn reade_stream()
// {
//     stream.readable().await?;

//     // Creating the buffer **after** the `await` prevents it from
//     // being stored in the async task.
//     let mut buf = [0; 4096];

//     // Try to read data, this may still fail with `WouldBlock`
//     // if the readiness event is a false positive.
//     match stream.try_read(&mut buf) {
//         Ok(0) => break,
//         Ok(n) => {
//             println!("read {} bytes", n);
//         }
//         Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
//             continue;
//         }
//         Err(e) => {
//             return Err(e.into());
//         }
//     }
// }

pub async fn send_data(socket: UdpSocket, data: Vec<u8>) -> Result<usize, ConnectionError>
{
    if data.len() > MAX_UDP_BUFFER {
        let listener = TcpListener::bind("127.0.0.1:9008").await?;
        let result = socket.send(b"0").await?;
        let now = Instant::now();
        // let mut futures = Vec::new();
        while now.elapsed().as_millis() < 1000 {
            // add timeout
            let (mut stream, sock_addr) =
                match timeout(Duration::from_millis(1000), listener.accept()).await {
                    Ok(v) => v?,
                    Err(_) => continue,
                };
            let data_to_send = data.clone();
            // futures.push(tokio::spawn(async move {
            let res = stream.write_all(&data_to_send).await;
            println!("shutdown called");
            stream.shutdown().await?;
            println!("shutdown called 2");
            // return res;
            // }));
        }
        // let _ = try_join_all(futures).await.map_err(|e| {
        //     ConnectionError::FailedToConnect(format!(
        //         "Failed to join tcp listener {}",
        //         e
        //     ))
        // })?;
        println!("after join called");
        return Ok(data.len());
        // match result {
        //     Ok(items) => {
        //         return Ok(data.len());
        //     },
        //     Err(err) => {
        //         return Err(ConnectionError::FailedToConnect(format!("Failed to send data to one or more receivers")));
        //     }
        // };
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

        let data_len_sent = send_data(client_sock, data_sent.clone()).await.unwrap();

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

        let data_len_sent = send_data(client_sock, data_sent.clone()).await.unwrap();

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
            tokio::spawn(async move { send_data(client_sock, for_sending).await }),
        )
        .unwrap();

        let data_len_sent = res.1.unwrap();
        let (data_received, addr) = res.0.unwrap();

        // let data_len_sent = send_data(client_sock, data_sent.clone())
        //     .await
        //     .unwrap();

        // let (data_received, addr) = receive_data(&server_sock, 2, |d: Duration| {
        //     d > Duration::from_millis(2000)
        // })
        // .await
        // .unwrap();

        assert_eq!(local_client, addr);
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
