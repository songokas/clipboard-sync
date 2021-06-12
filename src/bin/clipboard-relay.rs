// #![feature(ip)]
#![allow(dead_code)]
// #![feature(trait_alias)]
// #![feature(type_alias_impl_trait)

use std::convert::TryInto;
use std::net::SocketAddr;
use std::sync::Arc;
use x25519_dalek::{PublicKey, StaticSecret};

use log::{error, info};

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

#[path = "../destination_pool.rs"]
mod destination_pool;
#[path = "../relays/mod.rs"]
mod relays;
#[path = "../validation.rs"]
mod validation;

use crate::config::RelayConfig;
use crate::defaults::{BIND_ADDRESS, DEFAULT_MESSAGE_SIZE, KEY_SIZE};
use crate::encryption::random;
use crate::errors::CliError;
use crate::protocols::{Protocol, SocketPool};
use crate::relays::relay_packets;

const DEFAULT_MAX_GROUP_SIZE: u64 = 1000;
const DEFAULT_MAX_SOCKET_SIZE: u64 = 10;
const DEFAULT_SOCKET_KEEP_TIME: u16 = 60;
const DEFAULT_MAX_GROUPS_PER_IP: u16 = 10;
const DEFAULT_VALID_FOR: u16 = 300;

#[tokio::main]
async fn main() -> Result<(), CliError>
{
    let yaml = load_yaml!("relay.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let verbosity = matches.value_of("verbosity").unwrap_or("info");

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
