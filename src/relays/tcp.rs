use futures::stream::{self, StreamExt};
use log::debug;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use x25519_dalek::StaticSecret;

use crate::config::RelayConfig;
use crate::defaults::CONNECTION_TIMEOUT;
use crate::destination_pool::DestinationPool;
use crate::protocols::tcp::obtain_client_socket;
use crate::validation::get_group_id;

pub async fn relay_data(
    socket: &TcpListener,
    destination_pool: Arc<DestinationPool>,
    timeout_callback: impl Fn(Duration) -> bool,
    config: &RelayConfig,
) -> u64
{
    let now = Instant::now();
    let mut count = 0;
    while !timeout_callback(now.elapsed()) {
        let (stream, addr) = match timeout(Duration::from_millis(100), socket.accept()).await {
            Ok(v) => v.expect("tcp connection accept failed"),
            Err(_) => continue,
        };

        let timeout_with_duration = |d: Duration| -> bool {
            return d > Duration::from_millis(CONNECTION_TIMEOUT) && timeout_callback(d);
        };
        relay_stream(
            stream,
            destination_pool.clone(),
            addr,
            timeout_with_duration,
            config,
        )
        .await;
        count += 1;
    }
    return count;
}

async fn relay_stream(
    stream: TcpStream,
    destination_pool: Arc<DestinationPool>,
    addr: SocketAddr,
    timeout_callback: impl Fn(Duration) -> bool,
    config: &RelayConfig,
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
                for destination_stream in destination_streams.iter_mut() {
                    destination_stream
                        .shutdown()
                        .await
                        .expect("tcp stream shutdown error");
                }
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
                    let group_id = match get_group_id(
                        &buffer[..config.message_size],
                        &StaticSecret::from(config.private_key),
                        config.valid_for,
                    ) {
                        Ok(id) => id,
                        Err(e) => {
                            debug!("Group id not found in data with len {}. {}", read, e);
                            return total_read;
                        }
                    };
                    destination_pool.add_destination(group_id.clone(), addr.clone());
                    destination_streams =
                        stream::iter(destination_pool.get_destinations(&group_id))
                            .filter_map(|d| async move {
                                if d == addr {
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
                    initial = false;
                    buffer[config.message_size..].to_vec()
                } else {
                    buffer[..read].to_vec()
                };

                total_read += read as u64;

                for destination_stream in destination_streams.iter_mut() {
                    destination_stream
                        .write_all(&data)
                        .await
                        .expect("write full");
                    debug!(
                        "Relay from {} to {} len {}",
                        stream.peer_addr().expect("missing peer address"),
                        destination_stream.peer_addr().unwrap(),
                        data.len()
                    );
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(_) => {
                break;
            }
        };
    }
    return total_read;
}
