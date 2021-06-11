// #![feature(ip)]
#![allow(dead_code)]
// #![feature(trait_alias)]
// #![feature(type_alias_impl_trait)

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::RwLock;
use std::time::Instant;

use laminar::{Packet, SocketEvent};
use std::convert::TryInto;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use tokio::net::UdpSocket;
use tokio::time::Duration;
use x25519_dalek::{PublicKey, StaticSecret};

use log::{debug, error, info};

use clap::{load_yaml, App};
use env_logger::Env;
use std::sync::atomic::AtomicBool;

#[path = "../config.rs"]
mod config;
#[path = "../defaults.rs"]
mod defaults;
#[path = "../encryption.rs"]
mod encryption;
#[path = "../errors.rs"]
mod errors;
#[path = "../filesystem.rs"]
mod filesystem;
#[path = "../fragmenter.rs"]
mod fragmenter;
#[path = "../identity.rs"]
mod identity;
#[path = "../message.rs"]
mod message;
#[path = "../protocols/mod.rs"]
mod protocols;
#[path = "../socket.rs"]
mod socket;
#[cfg(test)]
#[path = "../test.rs"]
mod test;
#[path = "../time.rs"]
mod time;

use crate::defaults::{BIND_ADDRESS, DEFAULT_MESSAGE_SIZE, KEY_SIZE, MAX_UDP_BUFFER};
use crate::encryption::{decrypt_with_secret, random};
use crate::errors::{CliError, ConnectionError, ValidationError};
use crate::message::{GroupId, PublicMessage};
use crate::protocols::laminarpr::{LaminarReceiver, LaminarSender};
use crate::protocols::{Protocol, SocketPool};
use crate::socket::receive_from_timeout;
use crate::time::{get_time, is_timestamp_valid};

const DEFAULT_MAX_GROUP_SIZE: u64 = 1000;
const DEFAULT_MAX_SOCKET_SIZE: u64 = 10;
const DEFAULT_SOCKET_KEEP_TIME: u16 = 60;
const DEFAULT_MAX_GROUPS_PER_IP: u16 = 10;
const DEFAULT_VALID_FOR: u16 = 300;

#[derive(Debug, Clone)]
struct RelayConfig
{
    pub max_groups: u64,
    pub max_sockets: u64,
    pub keep_sockets_for: u16,
    pub message_size: usize,
    pub private_key: [u8; KEY_SIZE],
    pub valid_for: u16,
    pub max_per_ip: u16,
}

struct DestinationPool
{
    addresses: RwLock<HashMap<GroupId, HashMap<SocketAddr, Instant>>>,
    ips: RwLock<HashMap<IpAddr, HashSet<GroupId>>>,
    max_sockets: usize,
    max_groups: usize,
    max_per_ip: usize,
}

impl DestinationPool
{
    pub fn new(max_groups: usize, max_sockets: usize, max_per_ip: usize) -> Self
    {
        return Self {
            addresses: RwLock::new(HashMap::new()),
            ips: RwLock::new(HashMap::new()),
            max_groups,
            max_sockets,
            max_per_ip,
        };
    }

    pub fn get_destinations(&self, group_id: &GroupId) -> Vec<SocketAddr>
    {
        match self.addresses.read() {
            Ok(h) => h
                .get(group_id)
                .map(|h| h.keys().cloned().collect())
                .unwrap_or(vec![]),
            Err(_) => vec![],
        }
    }

    pub fn add_destination(&self, group_id: GroupId, address: SocketAddr)
    {
        match self.addresses.write() {
            Ok(mut all) => {
                if all.len() >= self.max_groups {
                    return;
                }

                let result = match self.ips.read() {
                    Ok(t) => t.get(&address.ip()).map(|h| h.len()),
                    Err(_) => None,
                };

                match result {
                    Some(len) if len >= self.max_per_ip => return,
                    _ => (),
                };

                all.entry(group_id.clone())
                    .and_modify(|h| {
                        if h.len() < self.max_sockets {
                            h.insert(address, Instant::now());
                        }
                    })
                    .or_insert_with(|| {
                        let mut h = HashMap::new();

                        match self.ips.write() {
                            Ok(mut ip_list) => {
                                ip_list
                                    .entry(address.ip())
                                    .and_modify(|v| {
                                        v.insert(group_id.clone());
                                    })
                                    .or_insert_with(|| {
                                        let mut h = HashSet::new();
                                        h.insert(group_id);
                                        return h;
                                    });
                                h.insert(address, Instant::now());
                            }
                            Err(_) => (),
                        };
                        return h;
                    });
            }
            Err(e) => {
                error!("Failed to obtain write lock {}", e);
            }
        }
    }

    pub fn cleanup(&self, oldest: u64)
    {
        match self.addresses.write() {
            Ok(mut hash) => {
                hash.retain(|_, v| {
                    v.retain(|_, t| t.elapsed().as_secs() < oldest);
                    v.len() > 0
                });
            }
            Err(e) => {
                error!("Failed to obtain write lock {}", e);
            }
        };

        match self.ips.write() {
            Ok(mut ips) => match self.addresses.read() {
                Ok(addrs) => {
                    ips.retain(|_, v| {
                        v.retain(|group_id| addrs.contains_key(group_id));
                        v.len() > 0
                    });
                }
                _ => (),
            },
            _ => (),
        };
    }
}

// pub async fn relay_tcp(
//     socket: &TcpListener,
//     verifier: &impl IdentityVerifier,
//     max_len: usize,
//     timeout_callback: impl Fn(Duration) -> bool,
// ) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
// {
//     let now = Instant::now();
//     while !timeout_callback(now.elapsed()) {
//         let (stream, addr) = match timeout(Duration::from_millis(100), socket.accept()).await {
//             Ok(v) => v?,
//             Err(_) => continue,
//         };
//         verifier
//             .verify(&Identity::from(addr))
//             .ok_or_else(|| ConnectionError::InvalidSource(addr))?;

//         let timeout_with_duration = |d: Duration| -> bool {
//             return d > Duration::from_millis(CONNECTION_TIMEOUT) && timeout_callback(d);
//         };
//         return receive_stream(stream, addr, max_len, timeout_with_duration).await;
//     }
//     return Err(ConnectionError::Timeout(
//         "tcp receive".to_owned(),
//         now.elapsed(),
//     ));
// }

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

async fn relay_packets(
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

fn validate(buffer: &[u8], valid_for: u16) -> Result<PublicMessage, ValidationError>
{
    let message: PublicMessage = bincode::deserialize(buffer).map_err(|err| {
        ValidationError::DeserializeFailed(format!(
            "Validation invalid data provided: {}",
            (*err).to_string()
        ))
    })?;

    if !is_timestamp_valid(message.time, valid_for) {
        let now = get_time();
        let diff = if now >= message.time {
            now - message.time
        } else {
            message.time - now
        };
        return Err(ValidationError::InvalidTimestamp(diff, valid_for));
    }
    return Ok(message);
}

fn get_group_id(
    data: &[u8],
    secret: &StaticSecret,
    valid_for: u16,
) -> Result<Vec<u8>, ConnectionError>
{
    let message = validate(data, valid_for)?;
    let key = secret.diffie_hellman(&message.public_key);
    return Ok(decrypt_with_secret(message, &key)?);
}

#[tokio::main]
async fn main() -> Result<(), CliError>
{
    let yaml = load_yaml!("relay.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let verbosity = matches.value_of("verbosity").unwrap_or("debug");

    env_logger::Builder::from_env(Env::default().default_filter_or(verbosity)).init();

    let local_address = matches
        .value_of("bind-address")
        .unwrap_or_else(|| BIND_ADDRESS);

    let socket_addresses: Vec<SocketAddr> = local_address
        .split(",")
        .map(|v| {
            v.parse::<SocketAddr>().map_err(|_| {
                CliError::ArgumentError(format!("Invalid bind-address provided {}", v))
            })
        })
        .collect::<Result<Vec<SocketAddr>, CliError>>()?;

    let protocol = Protocol::from(matches.value_of("protocol"))?;

    let message_size = matches
        .value_of("message-size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MESSAGE_SIZE);
    let max_groups = matches
        .value_of("max-groups")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_GROUP_SIZE);
    let max_sockets = matches
        .value_of("max-sockets")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_SOCKET_SIZE);
    let keep_sockets_for = matches
        .value_of("keep-sockets-for")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SOCKET_KEEP_TIME);

    let valid_for = matches
        .value_of("valid-for")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_VALID_FOR);

    let max_per_ip = matches
        .value_of("max-per-ip")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_GROUPS_PER_IP);

    let private_key = matches
        .value_of("private-key")
        .map(|s| {
            let result: Result<[u8; KEY_SIZE], _> = s.as_bytes().try_into();
            match result {
                Ok(key) => Ok(StaticSecret::from(key)),
                Err(_) => Err(CliError::ArgumentError(format!(
                    "Invalid private key provided"
                ))),
            }
        })
        .unwrap_or_else(|| {
            let random_data = random(KEY_SIZE);
            let result: Result<[u8; KEY_SIZE], _> = random_data.try_into();
            match result {
                Ok(key) => Ok(StaticSecret::from(key)),
                Err(_) => Err(CliError::ArgumentError(format!(
                    "Unable to generate private key"
                ))),
            }
        })?;
    let private_key = StaticSecret::from(private_key);
    let public = PublicKey::from(&private_key);

    info!("Server public key {}", base64::encode(public.as_bytes()));

    let config = RelayConfig {
        max_groups,
        max_sockets,
        message_size,
        keep_sockets_for,
        private_key: private_key.to_bytes(),
        valid_for,
        max_per_ip,
    };

    let mut handles = Vec::new();
    let pool = Arc::new(SocketPool::new());
    let running = Arc::new(AtomicBool::new(true));
    for bind_address in socket_addresses {
        let receive = relay_packets(
            Arc::clone(&pool),
            bind_address,
            Arc::clone(&running),
            protocol.clone(),
            config.clone(),
        );

        handles.push(tokio::spawn(receive));
    }

    let result = futures::future::try_join_all(handles).await;
    match result {
        Ok(items) => {
            let mut result = Ok(());
            for res in items {
                match res {
                    Ok((name, c)) => {
                        info!("{} count {}", name, c);
                    }
                    Err(e) => {
                        error!("error: {}", e);
                        result = Err(e);
                    }
                }
            }
            return result;
        }
        Err(err) => {
            error!("{}", err);
            return Err(CliError::JoinError(err));
        }
    };
}
