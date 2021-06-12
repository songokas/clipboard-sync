use futures::stream::{self, StreamExt};
use log::{debug, error, warn};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use x25519_dalek::StaticSecret;

use crate::config::RelayConfig;
use crate::defaults::DATA_TIMEOUT;
use crate::destination_pool::DestinationPool;
use crate::errors::ConnectionError;
use crate::protocols::tcp::obtain_client_socket;
use crate::validation::get_group_id;

pub async fn relay_data(
    socket: &TcpListener,
    destination_pool: Arc<DestinationPool>,
    running: Arc<AtomicBool>,
    config: &RelayConfig,
) -> u64
{
    let count = Arc::new(AtomicU64::new(0));
    while running.load(Ordering::Relaxed) {
        let (stream, addr) = match timeout(Duration::from_millis(100), socket.accept()).await {
            Ok(v) => v.expect("tcp connection accept failed"),
            Err(_) => continue,
        };
        let srunning = running.clone();
        let timeout_with_duration = move |d: Duration| -> bool {
            return d > Duration::from_millis(DATA_TIMEOUT) || !srunning.load(Ordering::Relaxed);
        };
        tokio::spawn(relay_stream(
            stream,
            destination_pool.clone(),
            addr,
            timeout_with_duration,
            config.clone(),
            count.clone(),
        ));
    }
    return count.load(Ordering::Relaxed);
}

async fn relay_stream(
    stream: TcpStream,
    destination_pool: Arc<DestinationPool>,
    from_addr: SocketAddr,
    timeout_callback: impl Fn(Duration) -> bool,
    config: RelayConfig,
    count: Arc<AtomicU64>,
) -> u64
{
    let mut buffer = [0; 10000];
    let now = Instant::now();
    let mut total_read = 0;
    let mut destination_streams: Vec<TcpStream> = Vec::new();
    let local_addr = stream.local_addr().expect("tcp local address expected");
    let mut initial = true;

    // let mut initial_data = Vec::new();
    while !timeout_callback(now.elapsed()) {
        stream.readable().await.expect("readable stream error");

        match stream.try_read(&mut buffer) {
            Ok(0) => {
                close_streams(&mut destination_streams).await;
                count.fetch_add(1, Ordering::Relaxed);
                break;
            }
            Ok(read) => {
                if read < config.message_size {
                    debug!(
                        "Ignoring packet without header from {}. Packet length {} expected {}",
                        stream.peer_addr().expect("missing peer address"),
                        read + 1,
                        config.message_size + 1
                    );
                    continue;
                }
                let data = if initial {
                    destination_streams = match get_streams(
                        &buffer[..config.message_size],
                        &destination_pool,
                        local_addr,
                        from_addr,
                        read,
                        &config,
                    )
                    .await
                    {
                        Ok(s) => s,
                        Err(_) => break,
                    };
                    initial = false;
                    buffer[config.message_size..].to_vec()
                } else {
                    buffer[..read].to_vec()
                };

                total_read += read as u64;

                send_data(&mut destination_streams, data, &from_addr).await;
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

async fn close_streams(destination_streams: &mut Vec<TcpStream>)
{
    for destination_stream in destination_streams.iter_mut() {
        destination_stream
            .shutdown()
            .await
            .expect("tcp stream shutdown error");
    }
}

async fn send_data(destination_streams: &mut Vec<TcpStream>, data: Vec<u8>, from_addr: &SocketAddr)
{
    for destination_stream in destination_streams.iter_mut() {
        destination_stream
            .write_all(&data)
            .await
            .expect("write full");
        debug!(
            "Relay from {} to {} len {}",
            from_addr,
            destination_stream.peer_addr().unwrap(),
            data.len()
        );
    }
}

async fn get_streams(
    buffer: &[u8],
    destination_pool: &DestinationPool,
    local_addr: SocketAddr,
    from_addr: SocketAddr,
    read: usize,
    config: &RelayConfig,
) -> Result<Vec<TcpStream>, ConnectionError>
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
    destination_pool.add_destination(group_id.clone(), from_addr.clone());
    let streams = stream::iter(destination_pool.get_destinations(&group_id))
        .filter_map(|d| async move {
            if d == from_addr {
                None
            } else {
                if let Some(s) = obtain_client_socket(local_addr).ok() {
                    s.connect(d).await.ok()
                } else {
                    None
                }
            }
        })
        .collect::<Vec<TcpStream>>()
        .await;
    return Ok(streams);
}
