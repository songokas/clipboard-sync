use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use std::time::Instant;
use tokio::net::TcpStream;
use tokio::time::Duration;

use crate::errors::ConnectionError;

pub async fn receive_stream(
    stream: Arc<TcpStream>,
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
                // if data[-4..0] ==
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

pub async fn stream_data(stream: &TcpStream, data: Vec<u8>) -> Result<usize, ConnectionError>
{
    let mut total_written = 0;
    loop {
        stream.writable().await?;
        match stream.try_write(&data[total_written..]) {
            Ok(n) => {
                total_written += n;
                if data.len() <= total_written {
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
    return Ok(total_written);
}
