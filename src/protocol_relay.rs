// use futures::stream::futures_unordered::FuturesUnordered;
// use futures::stream::StreamExt;
use futures::stream::{self, StreamExt};
use laminar::{Packet, SocketEvent};
use log::{debug, error, info};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use x25519_dalek::StaticSecret;

use crate::defaults::{CONNECTION_TIMEOUT, KEY_SIZE, MAX_UDP_BUFFER};
use crate::destination_pool::DestinationPool;
use crate::encryption::decrypt_with_secret;
use crate::errors::{CliError, ConnectionError};
use crate::identity::validate_public;
use crate::protocols::laminarpr::{LaminarReceiver, LaminarSender};
use crate::protocols::tcp::obtain_client_socket;
use crate::protocols::{Protocol, SocketPool};
use crate::socket::receive_from_timeout;

#[derive(Debug, Clone)]
pub struct RelayConfig
{
    pub max_groups: u64,
    pub max_sockets: u64,
    pub keep_sockets_for: u16,
    pub message_size: usize,
    pub private_key: [u8; KEY_SIZE],
    pub valid_for: u16,
    pub max_per_ip: u16,
}

pub async fn relay_packets(
    pool: Arc<SocketPool>,
    local_address: SocketAddr,
    running: Arc<AtomicBool>,
    protocol: Protocol,
    config: RelayConfig,
) -> Result<(String, u64), CliError>
{
    let local_socket = match pool
        .obtain_server_socket(local_address.clone(), &protocol)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            running.store(false, Ordering::Relaxed);
            return Err(CliError::from(e));
        }
    };

    info!("Listen on {} protocol {}", local_address, protocol);

    let timeout = |_: Duration| !running.load(Ordering::Relaxed);
    let destination_pool = DestinationPool::new(
        config.max_groups as usize,
        config.max_sockets as usize,
        config.max_per_ip as usize,
    );
    let count = match protocol {
        Protocol::Basic | Protocol::Frames => {
            relay_data(
                local_socket.socket().expect("expected udp socke"),
                &destination_pool,
                timeout,
                &config,
            )
            .await
        }
        Protocol::Laminar => {
            relay_laminar(
                local_socket
                    .laminar_receiver()
                    .expect("expected laminar receiver"),
                local_socket
                    .laminar_sender()
                    .expect("expected laminar sender"),
                &destination_pool,
                timeout,
                &config,
            )
            .await
        }
        _ => {
            return Err(CliError::ArgumentError(format!(
                "Protocol {} is not supported for relay",
                protocol
            )))
        }
    };
    return Ok((format!("{} received", protocol), count));
}

pub async fn relay_tcp(
    socket: &TcpListener,
    destination_pool: &DestinationPool,
    timeout_callback: impl Fn(Duration) -> bool,
    config: &RelayConfig,
) -> u64
{
    let now = Instant::now();
    let mut count = 0;
    while !timeout_callback(now.elapsed()) {
        let (stream, addr) = match timeout(Duration::from_millis(100), socket.accept()).await {
            Ok(v) => v.unwrap(),
            Err(_) => continue,
        };

        let timeout_with_duration = |d: Duration| -> bool {
            return d > Duration::from_millis(CONNECTION_TIMEOUT) && timeout_callback(d);
        };
        relay_stream(
            stream,
            destination_pool,
            addr,
            timeout_with_duration,
            config,
        )
        .await;
        count += 1;
        destination_pool.cleanup(config.keep_sockets_for as u64);
    }
    return count;
}

async fn relay_stream(
    stream: TcpStream,
    destination_pool: &DestinationPool,
    addr: SocketAddr,
    timeout_callback: impl Fn(Duration) -> bool,
    config: &RelayConfig,
) -> u64
{
    let mut buffer = [0; 10000];
    // let mut data = Vec::new();
    let now = Instant::now();
    let mut total_read = 0;
    let mut destination_streams: Vec<TcpStream> = Vec::new();
    let local_addr = stream.local_addr().unwrap();
    while !timeout_callback(now.elapsed()) {
        stream.readable().await.unwrap();

        match stream.try_read(&mut buffer) {
            Ok(0) => {
                for destination_stream in destination_streams.iter_mut() {
                    destination_stream.shutdown().await.unwrap();
                }
                break;
            }
            Ok(read) => {
                let data = if total_read == 0 {
                    let group_id = match get_group_id(
                        &buffer[..config.message_size],
                        &StaticSecret::from(config.private_key),
                        config.valid_for,
                    ) {
                        Ok(id) => id,
                        Err(e) => {
                            debug!("Group id not found in len received {} {}", read, e);
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
                            // .collect::<FuturesUnordered<_>>()
                            .collect::<Vec<TcpStream>>()
                            .await;
                    buffer[config.message_size..read].to_vec()
                } else {
                    buffer[..read].to_vec()
                };

                total_read += read as u64;

                for destination_stream in destination_streams.iter_mut() {
                    destination_stream.write_all(&data).await.unwrap();
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

async fn relay_laminar(
    receiver: LaminarReceiver,
    sender: LaminarSender,
    destination_pool: &DestinationPool,
    timeout_callback: impl Fn(Duration) -> bool,
    config: &RelayConfig,
) -> u64
{
    let now = Instant::now();
    let mut count = 0;
    let callback = |d: Duration| timeout_callback(d);

    let shared_sender = Arc::new(sender);

    while !callback(now.elapsed()) {
        let result = receiver.recv().await;

        match result {
            Some(socket_event) => match socket_event {
                SocketEvent::Packet(packet) => {
                    let addr: SocketAddr = packet.addr();
                    let data: &[u8] = packet.payload();

                    let group_id = match get_group_id(
                        &data[..config.message_size],
                        &StaticSecret::from(config.private_key.clone()),
                        config.valid_for,
                    ) {
                        Ok(id) => id,
                        Err(e) => {
                            debug!("Group id not found from {}", e);
                            continue;
                        }
                    };
                    let size = data[config.message_size..].len();

                    destination_pool.add_destination(group_id.clone(), addr.clone());
                    let destinations = destination_pool.get_destinations(&group_id);
                    let send_socket = shared_sender.clone();
                    let data_to_send = data[config.message_size..].to_vec();

                    tokio::spawn(async move {
                        for destination in destinations {
                            if destination == addr {
                                continue;
                            }
                            let send_packet =
                                Packet::reliable_ordered(destination, data_to_send.clone(), None);
                            if !send_socket.send(send_packet).await {
                                error!("Failed to send to {} from {}", destination, addr);
                            } else {
                                debug!("Relay from {} to {} len {}", addr, destination, size);
                            }
                        }
                    });

                    count += 1;

                    destination_pool.cleanup(config.keep_sockets_for as u64);
                }
                _ => continue,
            },
            _ => thread::sleep(Duration::from_millis(5)),
        }
    }
    return count;
}

async fn relay_data(
    socket: Arc<UdpSocket>,
    destination_pool: &DestinationPool,
    timeout_callback: impl Fn(Duration) -> bool,
    config: &RelayConfig,
) -> u64
{
    let mut buffer = [0; MAX_UDP_BUFFER];
    let callback = |d: Duration| timeout_callback(d);
    let now = Instant::now();
    let mut count = 0;
    while !callback(now.elapsed()) {
        let (read, addr) = match receive_from_timeout(&socket, &mut buffer, callback).await {
            Ok(a) => a,
            Err(e) => {
                debug!("Received timeout error {}", e);
                continue;
            }
        };

        let group_id = match get_group_id(
            &buffer[..config.message_size],
            &StaticSecret::from(config.private_key),
            config.valid_for,
        ) {
            Ok(id) => id,
            Err(e) => {
                debug!("Group id not found in len received {} {}", read, e);
                continue;
            }
        };
        destination_pool.add_destination(group_id.clone(), addr.clone());
        let destinations = destination_pool.get_destinations(&group_id);
        let send_socket = socket.clone();
        let message_limit = config.message_size;
        tokio::spawn(async move {
            for destination in destinations {
                if destination == addr {
                    continue;
                }
                match send_socket
                    .send_to(&buffer[message_limit..read], destination)
                    .await
                {
                    Ok(_) => {
                        debug!(
                            "Relay from {} to {} len {}",
                            addr,
                            destination,
                            buffer[message_limit..read].len(),
                        );
                    }
                    Err(e) => {
                        error!("Failed to send to {} {}", destination, e);
                    }
                };
            }
        });
        count += 1;

        destination_pool.cleanup(config.keep_sockets_for as u64);
    }
    return count;
}

fn get_group_id(
    data: &[u8],
    secret: &StaticSecret,
    valid_for: u16,
) -> Result<Vec<u8>, ConnectionError>
{
    let message = validate_public(data, valid_for)?;
    let key = secret.diffie_hellman(&message.public_key);
    return Ok(decrypt_with_secret(message, &key)?);
}
