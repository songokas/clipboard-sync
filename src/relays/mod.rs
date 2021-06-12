use log::{debug, info};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::Duration;

use crate::config::RelayConfig;
use crate::destination_pool::DestinationPool;
use crate::errors::CliError;
use crate::protocols::{Protocol, SocketPool};
use crate::time::run_every;

#[path = "laminar.rs"]
mod laminarpr;
pub mod tcp;
mod udp;

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
    let destination_pool = Arc::new(DestinationPool::new(
        config.max_groups as usize,
        config.max_sockets as usize,
        config.max_per_ip as usize,
    ));
    let cpool = destination_pool.clone();
    let destination_cleanup = move || {
        let (addr_len, ips_len) = cpool.cleanup(60);
        debug!(
            "Destination cleanup hash len {} ip limits {}",
            addr_len
                .map(|l| l.to_string())
                .unwrap_or("unknown".to_owned()),
            ips_len
                .map(|l| l.to_string())
                .unwrap_or("unknown".to_owned())
        );
        // stop cleanup when relay_packets return
        Arc::strong_count(&cpool) > 1
    };

    tokio::spawn(run_every(
        Duration::from_secs(30),
        running.clone(),
        destination_cleanup,
    ));

    let count = match protocol {
        Protocol::Basic => {
            udp::relay_data(
                local_socket.socket().expect("expected udp socke"),
                destination_pool.clone(),
                timeout,
                &config,
            )
            .await
        }
        Protocol::Laminar => {
            laminarpr::relay_data(
                local_socket
                    .laminar_receiver()
                    .expect("expected laminar receiver"),
                local_socket
                    .laminar_sender()
                    .expect("expected laminar sender"),
                destination_pool.clone(),
                timeout,
                &config,
            )
            .await
        }
        Protocol::Tcp => {
            tcp::relay_data(
                local_socket.tcp_listener().expect("expected tcp socke"),
                destination_pool.clone(),
                running.clone(),
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
