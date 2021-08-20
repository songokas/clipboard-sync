use log::{debug, error};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::time::Duration;
use x25519_dalek::StaticSecret;

use crate::config::RelayConfig;
use crate::defaults::MAX_UDP_BUFFER;
use crate::destination_pool::DestinationPool;
use crate::socket::receive_from_timeout;
use crate::validation::get_group_id;

pub async fn relay_data(
    socket: Arc<UdpSocket>,
    destination_pool: Arc<DestinationPool>,
    timeout_callback: impl Fn(Duration) -> bool,
    config: &RelayConfig,
) -> u64
{
    let mut buffer = [0; MAX_UDP_BUFFER];
    let callback = |d: Duration| timeout_callback(d);
    let now = Instant::now();
    let count = Arc::new(AtomicU64::new(0));
    while !callback(now.elapsed()) {
        let (read, addr) = match receive_from_timeout(&socket, &mut buffer, callback).await {
            Ok(a) => a,
            Err(e) => {
                debug!("Received timeout error {}", e);
                continue;
            }
        };

        if read < config.message_size {
            debug!(
                "Ignoring packet without header from {}. Packet length {} expected {}",
                addr,
                read + 1,
                config.message_size + 1
            );
            continue;
        }

        let group_id = match get_group_id(
            &buffer[..config.message_size],
            &StaticSecret::from(config.private_key),
            config.valid_for,
        ) {
            Ok(id) => id,
            Err(e) => {
                debug!("Group id not found in data with len {}. {}", read, e);
                continue;
            }
        };

        if let Err(e) = destination_pool.add_destination(group_id, addr) {
            error!("Add destination error: {}", e);
            continue;
        }

        tokio::spawn(send_to(
            socket.clone(),
            buffer[config.message_size..read].to_vec(),
            destination_pool.get_destinations(&group_id),
            addr,
            count.clone(),
        ));
    }
    count.load(Ordering::Relaxed)
}

async fn send_to(
    socket: Arc<UdpSocket>,
    data_to_send: Vec<u8>,
    destinations: Vec<SocketAddr>,
    from_addr: SocketAddr,
    count: Arc<AtomicU64>,
)
{
    for destination in destinations {
        if destination == from_addr {
            continue;
        }
        match socket.send_to(&data_to_send, destination).await {
            Ok(_) => {
                debug!(
                    "Relay from {} to {} len {}",
                    from_addr,
                    destination,
                    data_to_send.len(),
                );
                count.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                error!("Failed to send to {} {}", destination, e);
            }
        };
    }
}
