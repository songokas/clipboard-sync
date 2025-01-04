use log::info;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::config::RelayConfig;
use crate::errors::{CliError, ConnectionError};
use crate::pools::destination_pool::DestinationPool;
use crate::protocol::Protocol;
use crate::protocols;

pub mod tcp;
mod udp;

pub async fn relay_packets(
    local_address: SocketAddr,
    protocol: Protocol,
    config: RelayConfig,
) -> Result<(String, u64), CliError> {
    info!("Listen on {} protocol {}", local_address, protocol);

    let destination_pool = Arc::new(DestinationPool::new(
        config.max_groups as usize,
        config.max_sockets as usize,
        config.max_per_ip as usize,
    ));

    let count = match protocol {
        Protocol::Basic => {
            let socket = UdpSocket::bind(local_address)
                .await
                .map_err(|e| ConnectionError::BindError(local_address, e))?;
            udp::relay_data(socket, destination_pool.clone(), &config).await
        }
        Protocol::Tcp => {
            let socket = protocols::tcp::obtain_server_socket(local_address)?;
            tcp::relay_data(socket, destination_pool.clone(), config).await
        }
        #[allow(unreachable_patterns)]
        _ => {
            return Err(CliError::ArgumentError(format!(
                "Protocol {} is not supported for relay",
                protocol
            )))
        }
    };
    Ok((format!("{} received", protocol), count))
}
