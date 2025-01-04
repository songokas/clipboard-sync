use log::{debug, error, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::select;
use x25519_dalek::StaticSecret;

use crate::config::RelayConfig;
use crate::defaults::{INIDICATION_SIZE, MAX_UDP_BUFFER};
use crate::pools::destination_pool::DestinationPool;
use crate::socket::split_into_messages;
use crate::validation::get_group_id;

pub async fn relay_data(
    socket: UdpSocket,
    destination_pool: Arc<DestinationPool>,
    config: &RelayConfig,
) -> u64 {
    let mut buffer = [0; MAX_UDP_BUFFER];
    let socket = Arc::new(socket);
    let mut success_count = 0;
    loop {
        select! {
            new_data = socket.recv_from(&mut buffer) => {
                let Ok((read, remote_addr)) = new_data else {
                    break;
                };

                debug!("Received data_size={read} remote_addr={remote_addr}");

                let header_size = INIDICATION_SIZE + config.message_size;

                if read < header_size {
                    debug!(
                        "Ignoring packet without header from {}. Packet length {} expected {}",
                        remote_addr,
                        read + 1,
                        config.message_size + 1
                    );
                    continue;
                }

                let messages = split_into_messages(&buffer[..read]);
                if messages.is_empty() {
                    warn!("Unknown data received remote_addr={remote_addr} size_read={read}");
                }
                for message in messages {
                    if message.len() < config.message_size {
                        debug!("Ignoring message len={} expected_size={}", message.len(), config.message_size);
                        continue;
                    }
                    let group_id = match get_group_id(
                        &message[..config.message_size],
                        &StaticSecret::from(config.private_key),
                        config.valid_for,
                    ) {
                        Ok(id) => id,
                        Err(e) => {
                            debug!("Group id not found in data with len {}. {}", read, e);
                            continue;
                        }
                    };

                    if let Err(e) = destination_pool.add_destination(group_id, remote_addr) {
                        error!("Add destination error: {}", e);
                        continue;
                    }

                    let data = message[config.message_size..].to_vec();
                    let data = [(data.len() as u64).to_be_bytes().to_vec(), data].concat();

                    let (sent_count, data_size) = send_to(
                        socket.clone(),
                        data,
                        destination_pool.get_destinations(&group_id),
                        remote_addr,
                    ).await;

                    debug!("Relay finished total bytes sent,received {data_size} to {sent_count} destinations");
                    success_count += sent_count;
                }
            }
        }
    }
    success_count
}

async fn send_to(
    socket: Arc<UdpSocket>,
    data_to_send: Vec<u8>,
    destinations: Vec<SocketAddr>,
    from_addr: SocketAddr,
) -> (u64, usize) {
    let mut success_count = 0;
    let data_size = data_to_send.len();
    for remote_addr in destinations {
        if remote_addr == from_addr {
            continue;
        }
        match socket.send_to(&data_to_send, remote_addr).await {
            Ok(s) => {
                debug!(
                    "Relay from={from_addr} to={remote_addr} data_size={} network_size={s}",
                    data_to_send.len(),
                );
                success_count += 1;
            }
            Err(e) => {
                error!("Failed to send to {} {}", remote_addr, e);
            }
        };
    }
    (success_count, data_size)
}
