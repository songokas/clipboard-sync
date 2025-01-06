use indexmap::{indexset, IndexSet};
use log::trace;
use tokio::time::timeout;

use core::cmp::min;
use core::net::SocketAddr;
use core::time::Duration;
use std::io;
use std::net::IpAddr;
use std::time::Instant;
use tokio::net::UdpSocket;

use crate::config::SendGroups;
use crate::errors::ConnectionError;
use crate::protocol::Protocol;
use crate::protocols::basic::obtain_client_socket;
use crate::socket::{to_socket_address, Destination};

/// packet size: packet type, port, server name len, server name
const MULTICAST_PACKET_SIZE: usize = 1 + 2 + 1 + u8::MAX as usize;

#[derive(Debug)]
pub enum MulticastMessage {
    Query(Protocol),
    // port number
    Advertise {
        port: u16,
        server_name: Option<String>,
    },
}

impl TryFrom<&[u8]> for MulticastMessage {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value.first() {
            Some(i) if i == &0 => {
                let protocol = Protocol::try_from(*value.get(1).ok_or(())?)?;
                Ok(Self::Query(protocol))
            }
            Some(i) if i == &1 => {
                let port =
                    u16::from_be_bytes(value.get(1..3).ok_or(())?.try_into().map_err(|_| ())?);
                let server_len = (*value.get(3).ok_or(())?) as usize;
                let server_name = if server_len == 0 {
                    None
                } else {
                    String::from_utf8_lossy(value.get(4..4 + server_len).ok_or(())?)
                        .to_string()
                        .into()
                };
                Ok(Self::Advertise { port, server_name })
            }

            _ => Err(()),
        }
    }
}

impl From<MulticastMessage> for Vec<u8> {
    fn from(val: MulticastMessage) -> Self {
        match val {
            MulticastMessage::Query(protocol) => {
                vec![0, protocol as u8]
            }
            MulticastMessage::Advertise { port, server_name } => {
                let bytes = port.to_be_bytes();
                let mut bytes = vec![1, bytes[0], bytes[1]];
                if let Some(mut s) = server_name {
                    s.truncate(u8::MAX as usize);
                    bytes.push(s.len() as u8);
                    bytes.extend_from_slice(s.as_bytes());
                } else {
                    bytes.push(0);
                }

                bytes
            }
        }
    }
}

pub fn to_multicast_ips(local_addr: SocketAddr, groups: &SendGroups) -> IndexSet<IpAddr> {
    let mut multicast_ips = IndexSet::new();
    let available_addresses = indexset! { local_addr };
    for (_, group) in groups {
        for (remote_host, _) in &group.allowed_hosts {
            let (_, remote_addr) = match to_socket_address(&available_addresses, remote_host) {
                Ok(a) => a,
                _ => {
                    // warn!("Unable to parse or retrieve address for {remote_host} from available {available_addresses:?}", );
                    continue;
                }
            };

            if remote_addr.ip().is_multicast() {
                multicast_ips.insert(remote_addr.ip());
            }
        }
    }
    multicast_ips
}

pub fn join_multicast(
    sock: &UdpSocket,
    multicast_addr: IpAddr,
    interface_addr: IpAddr,
) -> io::Result<()> {
    match multicast_addr {
        IpAddr::V4(multicast_ipv4) => {
            if let IpAddr::V4(interface_ipv4) = interface_addr {
                trace!("Join multicast={multicast_ipv4} interface={interface_ipv4}");
                sock.set_multicast_loop_v4(false).unwrap_or(());
                sock.join_multicast_v4(multicast_ipv4, interface_ipv4)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid ipv4 address {}", interface_addr),
                ))
            }
        }
        IpAddr::V6(multicast_ipv6) => {
            sock.set_multicast_loop_v6(false).unwrap_or(());
            sock.join_multicast_v6(&multicast_ipv6, 0)
        }
    }
}

pub async fn resolve_multicast(
    bind_ip: IpAddr,
    remote_addr: SocketAddr,
    protocol: Protocol,
    connect_timeout: Duration,
) -> Result<Vec<Destination>, ConnectionError> {
    let socket = obtain_client_socket(SocketAddr::new(bind_ip, 0), remote_addr).await?;
    let message = MulticastMessage::Query(protocol);

    trace!("Multicast query {message:?} to remote_addr={remote_addr}");

    let now = Instant::now();
    let mut destinations = Vec::new();

    let mut bytes: Vec<u8> = message.into();
    bytes.resize(MULTICAST_PACKET_SIZE, 0);
    socket.send_to(&bytes, remote_addr).await?;
    let mut wait = connect_timeout / 2;

    loop {
        match wait_for_packet(&socket, wait).await {
            Ok(Some(d)) => {
                destinations.push(d);
                // if we get a destination lets wait for 200ms more if possible
                wait = min(Duration::from_millis(200), connect_timeout - now.elapsed());
            }
            Ok(None) if destinations.is_empty() => {
                if now.elapsed() > connect_timeout {
                    return Err(ConnectionError::Timeout("multicast", connect_timeout));
                }
                // lets try another packet
                socket.send_to(&bytes, remote_addr).await?;
                wait = connect_timeout - now.elapsed();
            }
            Err(e) if destinations.is_empty() => return Err(e),
            Ok(None) | Err(_) => {
                break;
            }
        }
    }
    Ok(destinations)
}

async fn wait_for_packet(
    socket: &UdpSocket,
    wait: Duration,
) -> Result<Option<Destination>, ConnectionError> {
    let mut buf = [0; MULTICAST_PACKET_SIZE];

    let (size, peer_addr) = match timeout(wait, socket.recv_from(&mut buf)).await {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(None),
    };
    let message = MulticastMessage::try_from(&buf[..size]).map_err(|_| {
        ConnectionError::InvalidBuffer(format!(
            "Invalid multicast message received {size} remote_addr={peer_addr}"
        ))
    })?;
    trace!("Multicast reply {message:?} from remote_addr={peer_addr}");
    match message {
        MulticastMessage::Advertise { port, server_name } => {
            let new_addr = SocketAddr::new(peer_addr.ip(), port);
            Ok(Some(Destination::new(
                server_name.unwrap_or_else(|| new_addr.to_string()),
                new_addr,
            )))
        }
        _ => Ok(None),
    }
}

pub async fn advertise_service(
    multicast_socket: &UdpSocket,
    protocol: Protocol,
    port: u16,
    server_name: Option<String>,
) -> Result<(), ConnectionError> {
    let mut buf = [0; MULTICAST_PACKET_SIZE];

    let (size, peer_addr) = multicast_socket.recv_from(&mut buf).await?;
    trace!("Received multicast size={size} remote_addr={peer_addr}");
    let Ok(message) = MulticastMessage::try_from(&buf[..size]) else {
        return Err(ConnectionError::InvalidBuffer(format!(
            "Invalid multicast message remote_addr={peer_addr}"
        )));
    };
    if matches!(message, MulticastMessage::Query(p) if p == protocol) {
        let message = MulticastMessage::Advertise { port, server_name };
        trace!("Multicast advertise={message:?} to remote_addr={peer_addr}");
        let mut bytes: Vec<u8> = message.into();
        bytes.resize(MULTICAST_PACKET_SIZE, 0);
        multicast_socket.send_to(&bytes, peer_addr).await?;
    }
    Ok(())
}

pub async fn create_multicast_socket(
    local_addr: Option<SocketAddr>,
    multicast_ips: IndexSet<IpAddr>,
) -> Result<Option<UdpSocket>, std::io::Error> {
    let Some(local_addr) = local_addr else {
        return Ok(None);
    };
    if !multicast_ips.is_empty() {
        let multicast_socket = UdpSocket::bind(local_addr).await?;
        let mut joined = false;
        for ip in multicast_ips.into_iter().filter(|i| i.is_multicast()) {
            join_multicast(&multicast_socket, ip, local_addr.ip())?;
            joined = true;
        }
        Ok(joined.then_some(multicast_socket))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_multicast_query() {
        let bytes = [0_u8, 1];
        let message = MulticastMessage::try_from(&bytes[..]).unwrap();
        assert!(matches!(message, MulticastMessage::Query(_)));
        let received_bytes: Vec<u8> = message.into();
        assert_eq!(received_bytes, bytes);
    }

    #[test]
    fn test_multicast_advertise_with_server_name() {
        let message = MulticastMessage::Advertise {
            port: 8900,
            server_name: "test-name".to_string().into(),
        };
        let bytes: Vec<u8> = message.into();
        let message: MulticastMessage = bytes.as_slice().try_into().unwrap();
        match message {
            MulticastMessage::Advertise { port, server_name } => {
                assert_eq!(port, 8900);
                assert_eq!(server_name, "test-name".to_string().into());
            }
            _ => panic!("wrong message"),
        }
    }

    #[test]
    fn test_multicast_advertise_no_server_name() {
        let message = MulticastMessage::Advertise {
            port: 8900,
            server_name: None,
        };
        let bytes: Vec<u8> = message.into();
        let message: MulticastMessage = bytes.as_slice().try_into().unwrap();
        match message {
            MulticastMessage::Advertise { port, server_name } => {
                assert_eq!(port, 8900);
                assert_eq!(server_name, None);
            }
            _ => panic!("wrong message"),
        }
    }
}
