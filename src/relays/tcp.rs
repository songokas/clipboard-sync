use futures::stream::{self, StreamExt};
use log::{debug, error, warn};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use x25519_dalek::StaticSecret;

use crate::config::RelayConfig;
use crate::defaults::DATA_TIMEOUT;
use crate::destination_pool::DestinationPool;
use crate::errors::ConnectionError;
use crate::socket::StreamPool;
use crate::stream::stream_data;
use crate::validation::get_group_id;

pub async fn relay_data(
    listener: (&TcpListener, Arc<StreamPool>),
    destination_pool: Arc<DestinationPool>,
    running: Arc<AtomicBool>,
    config: &RelayConfig,
) -> u64
{
    let (socket, pool) = listener;
    let count = Arc::new(AtomicU64::new(0));
    while running.load(Ordering::Relaxed) {
        let (stream, addr) = match timeout(Duration::from_millis(100), socket.accept()).await {
            Ok(v) => {
                let (s, a) = v.expect("socket stream expected");
                let stream = Arc::new(s);
                (stream, a)
            }
            Err(_) => match pool.get_stream_with_data().await {
                Some(s) => {
                    let addr = s.peer_addr().unwrap();
                    (s, addr)
                }
                None => continue,
            },
        };
        let srunning = running.clone();
        let timeout_with_duration = move |d: Duration| -> bool {
            return d > Duration::from_millis(DATA_TIMEOUT) || !srunning.load(Ordering::Relaxed);
        };
        tokio::spawn(relay_stream(
            stream,
            destination_pool.clone(),
            pool.clone(),
            addr,
            timeout_with_duration,
            config.clone(),
            count.clone(),
        ));
    }
    return count.load(Ordering::Relaxed);
}

async fn relay_stream(
    stream: Arc<TcpStream>,
    destination_pool: Arc<DestinationPool>,
    stream_pool: Arc<StreamPool>,
    from_addr: SocketAddr,
    timeout_callback: impl Fn(Duration) -> bool,
    config: RelayConfig,
    count: Arc<AtomicU64>,
) -> u64
{
    let mut buffer = [0; 10000];
    let now = Instant::now();
    let mut total_read = 0;
    let mut destination_streams = Vec::new();
    let mut initial = true;

    while !timeout_callback(now.elapsed()) {
        stream.readable().await.expect("readable stream error");

        match stream.try_read(&mut buffer) {
            Ok(0) => {
                // close_streams(&mut destination_streams).await;
                count.fetch_add(1, Ordering::Relaxed);
                break;
            }
            Ok(read) => {
                if read < config.message_size {
                    debug!(
                        "Ignoring packet without header from {}. Packet length {} expected {}",
                        stream.peer_addr().expect("missing peer address"),
                        read,
                        config.message_size
                    );
                    continue;
                }
                let data = if initial {
                    destination_streams = match get_streams(
                        &buffer[..config.message_size],
                        &destination_pool,
                        &stream_pool,
                        from_addr,
                        read,
                        &config,
                    )
                    .await
                    {
                        Ok(s) => {
                            stream_pool.add(stream.clone()).await;
                            s
                        }
                        Err(e) => {
                            error!("Failed to obtain streams: {}", e);
                            break;
                        }
                    };
                    initial = false;
                    buffer[config.message_size..].to_vec()
                } else {
                    buffer[..read].to_vec()
                };

                total_read += read as u64;

                send_data(&destination_streams, data, &from_addr).await;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                error!("Failed to relay tcp connection {}", e);
                break;
            }
        };
    }
    return total_read;
}

// async fn close_streams(destination_streams: &mut Vec<TcpStream>)
// {
//     for destination_stream in destination_streams.iter_mut() {
//         if let Err(e) = destination_stream.shutdown().await {
//             error!("Tcp failed to close stream {}", e);
//         }
//     }
// }

async fn send_data(destination_streams: &[Arc<TcpStream>], data: Vec<u8>, from_addr: &SocketAddr)
{
    for destination_stream in destination_streams {
        let destination_addr = destination_stream.peer_addr().unwrap();
        if let Err(e) = stream_data(destination_stream, data.clone()).await {
            error!("Tcp failed to send data {}", e);
        }
        debug!(
            "Relay from {} to {} len {}",
            from_addr,
            destination_addr,
            data.len()
        );
    }
}

async fn get_streams(
    buffer: &[u8],
    destination_pool: &DestinationPool,
    stream_pool: &StreamPool,
    from_addr: SocketAddr,
    read: usize,
    config: &RelayConfig,
) -> Result<Vec<Arc<TcpStream>>, ConnectionError>
{
    let group_id = match get_group_id(
        &buffer,
        &StaticSecret::from(config.private_key),
        config.valid_for,
    ) {
        Ok(id) => id,
        Err(e) => {
            warn!("Group id not found in data with len {}. {}", read, e);
            return Err(e);
        }
    };
    destination_pool.add_destination(group_id.clone(), from_addr.clone())?;

    let streams = stream::iter(destination_pool.get_destinations(&group_id))
        .filter_map(|d| async move {
            if d == from_addr {
                None
            } else {
                stream_pool.get_by_destination(&d).await
            }
        })
        .collect::<Vec<Arc<TcpStream>>>()
        .await;
    return Ok(streams);
}
