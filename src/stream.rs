use std::collections::HashMap;
use std::convert::TryInto;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};

use crate::errors::ConnectionError;
use crate::errors::LimitError;
use crate::fragmenter::RelayEncryptor;

const INIDICATION_SIZE: usize = std::mem::size_of::<u64>();

pub async fn receive_stream(
    stream: Arc<TcpStream>,
    max_len: usize,
    timeout_callback: impl Fn(Duration) -> bool,
) -> Result<Vec<u8>, ConnectionError>
{
    let mut buffer = [0; 10000];
    let mut data = Vec::new();
    let now = Instant::now();
    let mut expected_size = 0;
    while !timeout_callback(now.elapsed()) {
        match timeout(Duration::from_millis(100), stream.readable()).await {
            Ok(_) => (),
            Err(_) => continue,
        }

        match stream.try_read(&mut buffer) {
            Ok(0) => {
                return Ok(data);
            }
            Ok(n) => {
                let data_read = if expected_size == 0 {
                    if n < INIDICATION_SIZE {
                        return Err(ConnectionError::InvalidBuffer(format!(
                            "Tcp stream received {}, but at least {} expected",
                            n, INIDICATION_SIZE
                        )));
                    }
                    let size: [u8; 8] = buffer[..INIDICATION_SIZE].try_into().map_err(|e| {
                        ConnectionError::InvalidBuffer(format!(
                            "Unable to receive data len to indicated size {}",
                            e
                        ))
                    })?;
                    expected_size = u64::from_be_bytes(size);
                    buffer[INIDICATION_SIZE..n].to_vec()
                } else {
                    buffer[0..n].to_vec()
                };

                if (data.len() + data_read.len()) > max_len {
                    return Err(ConnectionError::LimitReached {
                        received: data.len() + data_read.len(),
                        max_len,
                    });
                }
                data.extend(data_read);

                if expected_size != 0 && data.len() as u64 >= expected_size {
                    return Ok(data);
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
    return Err(ConnectionError::Timeout(
        "tcp receive stream".to_owned(),
        now.elapsed(),
    ));
}

pub async fn stream_data(
    stream: &TcpStream,
    encryptor: &impl RelayEncryptor,
    data: Vec<u8>,
    timeout_callback: impl Fn(Duration) -> bool,
) -> Result<usize, ConnectionError>
{
    let mut total_written = 0;
    let size: u64 = data.len().try_into().map_err(|e| {
        ConnectionError::InvalidBuffer(format!(
            "Unable to convert data len to indicated size {}",
            e
        ))
    })?;
    let size_indication = size.to_be_bytes().to_vec();
    let mut data_to_send = match encryptor.relay_header(&stream.peer_addr()?) {
        Ok(Some(mut h)) => {
            h.extend(size_indication);
            h
        }
        _ => size_indication,
    };
    data_to_send.extend(data);

    let now = Instant::now();

    while !timeout_callback(now.elapsed()) {
        if let Err(_) = timeout(Duration::from_millis(100), stream.writable()).await {
            continue;
        }
        match stream.try_write(&data_to_send[total_written..]) {
            Ok(n) => {
                total_written += n;
                if total_written >= data_to_send.len() {
                    // remove indication from bytes sent
                    total_written -= INIDICATION_SIZE;
                    return Ok(total_written);
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
    return Err(ConnectionError::Timeout(
        "tcp send stream".to_owned(),
        now.elapsed(),
    ));
}

pub struct StreamPool
{
    streams: RwLock<HashMap<SocketAddr, (Arc<TcpStream>, Instant)>>,
}

impl StreamPool
{
    pub fn new() -> Self
    {
        return StreamPool {
            streams: RwLock::new(HashMap::new()),
        };
    }

    pub async fn get_stream_with_data(&self) -> Option<Arc<TcpStream>>
    {
        let streams = self.streams.try_read().ok()?;
        for (_, (stream, _)) in streams.iter() {
            match timeout(Duration::from_millis(1), stream.readable()).await {
                Ok(r) => match r {
                    Ok(_) => return Some(stream.clone()),
                    Err(_) => continue,
                },
                Err(_) => continue,
            };
        }
        return None;
    }

    pub async fn get_by_destination(&self, addr: &SocketAddr) -> Option<Arc<TcpStream>>
    {
        self.streams.read().await.get(addr).map(|(s, _)| s.clone())
    }

    pub async fn add(&self, stream: Arc<TcpStream>) -> Option<(Arc<TcpStream>, Instant)>
    {
        let addr = match stream.peer_addr() {
            Ok(p) => p,
            Err(_) => return None,
        };
        self.streams
            .write()
            .await
            .insert(addr, (stream, Instant::now()))
    }

    pub async fn remove(&self, addr: &SocketAddr) -> Option<(Arc<TcpStream>, Instant)>
    {
        self.streams.write().await.remove(addr)
    }

    pub fn cleanup(&self, oldest: u64) -> Result<usize, LimitError>
    {
        let addr_len = match self.streams.try_write() {
            Ok(mut v) => {
                v.retain(|_, (_, t)| t.elapsed().as_secs() < oldest);
                v.len()
            }
            Err(e) => {
                return Err(LimitError::Lock(format!(
                    "Failed to obtain lock to cleanup streams {}",
                    e
                )));
            }
        };
        return Ok(addr_len);
    }
}

#[cfg(test)]
mod streamtest
{
    use tokio::net::TcpListener;

    use crate::protocols::tcp::connect_stream;

    use super::*;

    #[tokio::test]
    async fn test_stream_add()
    {
        let pool = StreamPool::new();

        let bind = "127.0.0.1:18329".parse::<SocketAddr>().unwrap();
        let listener = TcpListener::bind(bind).await.unwrap();
        tokio::spawn(async move {
            let mut arr = Vec::new();
            loop {
                let s = listener.accept().await.unwrap();
                arr.push(s);
            }
        });

        let addr = "127.0.0.1:8900".parse::<SocketAddr>().unwrap();
        let local_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();

        let result = pool.get_by_destination(&addr).await;
        assert!(result.is_none());

        let stream1 = connect_stream(local_addr, bind).await.unwrap();
        pool.add(Arc::new(stream1)).await;
        let stream2 = connect_stream(local_addr, bind).await.unwrap();
        pool.add(Arc::new(stream2)).await;

        let result = pool.get_by_destination(&bind).await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_stream_get_with_data()
    {
        let pool = StreamPool::new();

        let bind = "127.0.0.1:18339".parse::<SocketAddr>().unwrap();
        let listener = TcpListener::bind(bind).await.unwrap();
        tokio::spawn(async move {
            let mut arr = Vec::new();
            let data = [23, 32];
            loop {
                let (t, _) = listener.accept().await.unwrap();
                t.writable().await.unwrap();
                t.try_write(&data).unwrap();
                arr.push(t);
            }
        });

        let local_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        let stream1 = connect_stream(local_addr, bind).await.unwrap();
        pool.add(Arc::new(stream1)).await;
        let stream2 = connect_stream(local_addr, bind).await.unwrap();
        pool.add(Arc::new(stream2)).await;

        let result = pool.get_stream_with_data().await;
        assert!(result.is_some());
    }
}
