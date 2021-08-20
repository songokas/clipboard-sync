use futures::stream::{self, StreamExt};
use log::{debug, error, warn};
use std::collections::HashSet;
use std::convert::TryInto;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use x25519_dalek::StaticSecret;

use crate::config::RelayConfig;
use crate::defaults::{DATA_TIMEOUT, INIDICATION_SIZE};
use crate::destination_pool::DestinationPool;
use crate::errors::ConnectionError;
use crate::stream::{stream_data, StreamPool};
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
    let current_sockets = Arc::new(RwLock::new(HashSet::new()));
    while running.load(Ordering::Relaxed) {
        let (addr, stream) = match timeout(Duration::from_millis(100), socket.accept()).await {
            Ok(result) => {
                let (s, a) = match result {
                    Ok(d) => d,
                    Err(e) => {
                        error!("Failed to accept tcp connection {}", e);
                        continue;
                    }
                };
                let stream = Arc::new(s);
                (a, stream)
            }
            Err(_) => match pool
                .get_stream_with_data(&*current_sockets.read().await)
                .await
            {
                Some(s) => s,
                None => continue,
            },
        };

        current_sockets.write().await.insert(addr);

        let stream_callback = {
            let timeout_with_duration = {
                let srunning = running.clone();
                move |d: Duration| -> bool {
                    d > Duration::from_millis(DATA_TIMEOUT) || !srunning.load(Ordering::Relaxed)
                }
            };
            let cconfig = config.clone();
            let ccount = count.clone();
            let dpool = destination_pool.clone();
            let spool = pool.clone();
            relay_stream(
                stream,
                dpool,
                spool,
                addr,
                timeout_with_duration,
                cconfig,
                ccount,
            )
        };

        let csockets = current_sockets.clone();

        tokio::spawn(async move {
            match stream_callback.await {
                Ok(c) => debug!("Relay stream total bytes received {}", c),
                Err(e) => {
                    debug!("Relay stream failed: {}", e);
                }
            }
            csockets.write().await.remove(&addr);
        });
    }
    count.load(Ordering::Relaxed)
}

async fn relay_stream(
    stream: Arc<TcpStream>,
    destination_pool: Arc<DestinationPool>,
    stream_pool: Arc<StreamPool>,
    from_addr: SocketAddr,
    timeout_callback: impl Fn(Duration) -> bool + Clone,
    config: RelayConfig,
    count: Arc<AtomicU64>,
) -> Result<u64, ConnectionError>
{
    let mut buffer = [0; 10000];
    let now = Instant::now();
    let mut total_read = 0;
    let mut destination_streams = Vec::new();
    let mut initial = true;
    let mut expected_size = 0;
    let mut total_data_read = 0;

    while !timeout_callback(now.elapsed()) {
        match timeout(Duration::from_millis(100), stream.readable()).await {
            Ok(r) => r?,
            Err(_) => continue,
        };

        match stream.try_read(&mut buffer) {
            // stream closed
            Ok(0) => {
                count.fetch_add(1, Ordering::Relaxed);
                stream_pool.remove(&from_addr).await;
                return Ok(total_read);
            }
            Ok(read) => {
                let header_size = config.message_size + INIDICATION_SIZE;
                if read < header_size {
                    debug!(
                        "Ignoring packet without header from {}. Packet length {} expected {}",
                        stream
                            .peer_addr()
                            .map(|p| p.to_string())
                            .unwrap_or_else(|_| "missing peer address".into()),
                        read,
                        config.message_size
                    );
                    continue;
                }
                stream_pool.add(stream.clone()).await;

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
                        Ok(streams) => streams,
                        Err(e) => {
                            return Err(e);
                        }
                    };
                    initial = false;
                    let size: [u8; 8] = buffer[config.message_size..header_size]
                        .try_into()
                        .map_err(|e| {
                            ConnectionError::InvalidBuffer(format!(
                                "Unable to receive data len to indicated size {}",
                                e
                            ))
                        })?;
                    expected_size = u64::from_be_bytes(size);
                    total_data_read += read as u64 - header_size as u64;
                    buffer[config.message_size..read].to_vec()
                } else {
                    total_data_read += read as u64;
                    buffer[..read].to_vec()
                };

                total_read += read as u64;

                debug!(
                    "Tcp stream received {} expected {} total {}",
                    total_data_read, expected_size, total_read
                );

                send_data(
                    &destination_streams,
                    data,
                    &from_addr,
                    timeout_callback.clone(),
                )
                .await;

                if expected_size != 0 && total_data_read >= expected_size {
                    return Ok(total_read);
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                error!("Failed to relay tcp connection {}", e);
                return Err(ConnectionError::from(e));
            }
        };
    }
    Err(ConnectionError::Timeout(
        format!("tcp receive from {}", from_addr),
        now.elapsed(),
    ))
}

async fn send_data(
    destination_streams: &[Arc<TcpStream>],
    data: Vec<u8>,
    from_addr: &SocketAddr,
    timeout_callback: impl Fn(Duration) -> bool,
)
{
    for destination_stream in destination_streams {
        let destination_addr = match destination_stream.peer_addr() {
            Ok(a) => a.to_string(),
            Err(_) => "unknown peer".into(),
        };
        if let Err(e) = stream_data(destination_stream, data.clone(), |d| timeout_callback(d)).await
        {
            error!("Tcp failed to send data with length {} {}", data.len(), e);
            continue;
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
        buffer,
        &StaticSecret::from(config.private_key),
        config.valid_for,
    ) {
        Ok(id) => id,
        Err(e) => {
            warn!("Group id not found in data with len {}. {}", read, e);
            return Err(e);
        }
    };
    destination_pool.add_destination(group_id, from_addr)?;

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
    Ok(streams)
}
