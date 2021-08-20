use laminar::{Packet, SocketEvent};
use log::{debug, error};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use tokio::time::Duration;
use x25519_dalek::StaticSecret;

use crate::config::RelayConfig;
use crate::destination_pool::DestinationPool;
use crate::protocols::laminarpr::{LaminarReceiver, LaminarSender};
use crate::validation::get_group_id;

pub async fn relay_data(
    receiver: LaminarReceiver,
    sender: LaminarSender,
    destination_pool: Arc<DestinationPool>,
    timeout_callback: impl Fn(Duration) -> bool,
    config: &RelayConfig,
) -> u64
{
    let now = Instant::now();
    let callback = |d: Duration| timeout_callback(d);

    let shared_sender = Arc::new(sender);
    let count = Arc::new(AtomicU64::new(0));
    while !callback(now.elapsed()) {
        let result = receiver.recv().await;

        match result {
            Some(socket_event) => match socket_event {
                SocketEvent::Packet(packet) => {
                    let addr: SocketAddr = packet.addr();
                    let data: &[u8] = packet.payload();

                    if data.len() < config.message_size {
                        debug!(
                            "Ignoring packet without header from {}. Packet length {} expected {}",
                            addr,
                            data.len(),
                            config.message_size
                        );
                        continue;
                    }

                    let group_id = match get_group_id(
                        &data[..config.message_size],
                        &StaticSecret::from(config.private_key),
                        config.valid_for,
                    ) {
                        Ok(id) => id,
                        Err(e) => {
                            debug!("Group id not found from {}", e);
                            continue;
                        }
                    };
                    if let Err(e) = destination_pool.add_destination(group_id, addr) {
                        error!("Add destination error: {}", e);
                        continue;
                    }

                    tokio::spawn(send_to(
                        shared_sender.clone(),
                        data[config.message_size..].to_vec(),
                        destination_pool.get_destinations(&group_id),
                        addr,
                        count.clone(),
                    ));
                }
                _ => continue,
            },
            _ => thread::sleep(Duration::from_millis(1)),
        }
    }
    count.load(Ordering::Relaxed)
}

async fn send_to(
    sender: Arc<LaminarSender>,
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
        let send_packet = Packet::reliable_ordered(destination, data_to_send.clone(), None);
        if !sender.send(send_packet).await {
            error!("Failed to send to {} from {}", destination, from_addr);
        } else {
            debug!(
                "Relay from {} to {} len {}",
                from_addr,
                destination,
                data_to_send.len()
            );
            count.fetch_add(1, Ordering::Relaxed);
        }
    }
}
