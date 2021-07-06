// #![feature(ip)]
// #![feature(trait_alias)]
// #![feature(type_alias_impl_trait)

use indexmap::{indexset, IndexSet};
use std::convert::TryInto;
use std::net::SocketAddr;
use std::sync::Arc;
use x25519_dalek::{PublicKey, StaticSecret};

use log::{error, info};

use clap::{load_yaml, App};
use env_logger::Env;
use std::sync::atomic::AtomicBool;

use clipboard_sync::config::RelayConfig;
use clipboard_sync::defaults::{BIND_ADDRESS, DEFAULT_MESSAGE_SIZE, KEY_SIZE};
use clipboard_sync::encryption::random;
use clipboard_sync::errors::CliError;
use clipboard_sync::filesystem::read_file;
use clipboard_sync::protocols::{Protocol, SocketPool};
use clipboard_sync::relays::relay_packets;

const DEFAULT_MAX_GROUP_SIZE: u64 = 1000;
const DEFAULT_MAX_SOCKET_SIZE: u64 = 10;
const DEFAULT_SOCKET_KEEP_TIME: u16 = 60;
const DEFAULT_MAX_GROUPS_PER_IP: u16 = 10;
const DEFAULT_VALID_FOR: u16 = 300;
static BIND_ADDRESSES: &[&str] = &[BIND_ADDRESS, "0.0.0.0:8901", "0.0.0.0:8902"];

#[tokio::main]
async fn main() -> Result<(), CliError>
{
    let yaml = load_yaml!("relay.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let verbosity = matches.value_of("verbosity").unwrap_or("info");

    env_logger::Builder::from_env(Env::default().default_filter_or(verbosity)).init();

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
            let key_data: Vec<u8> = match read_file(s, KEY_SIZE) {
                Ok((file_contents, _)) => file_contents,
                Err(_) => s.as_bytes().to_vec(),
            };
            let key_size = key_data.len();
            let result: Result<[u8; KEY_SIZE], _> = key_data.try_into();
            match result {
                Ok(key) => Ok(StaticSecret::from(key)),
                Err(_) => Err(CliError::ArgumentError(format!(
                    "Invalid private key provided. Expected {} provided {}",
                    KEY_SIZE, key_size
                ))),
            }
        })
        .unwrap_or_else(|| {
            let random_data = random(KEY_SIZE);
            let result: Result<[u8; KEY_SIZE], _> = random_data.try_into();
            match result {
                Ok(key) => Ok(StaticSecret::from(key)),
                Err(_) => Err(CliError::ArgumentError(
                    "Unable to generate private key".into(),
                )),
            }
        })?;
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
    let pool = Arc::new(SocketPool::default());
    let running = Arc::new(AtomicBool::new(true));

    // clipboard-relay --protocol tcp --bind-address 0.0.0.0:8901 --protocol basic --bind-address
    let local_addresses = matches
        .values_of("bind-address")
        .map(|v| v.collect::<IndexSet<&str>>())
        .unwrap_or_else(|| {
            BIND_ADDRESSES
                .to_vec()
                .into_iter()
                .collect::<IndexSet<&str>>()
        });
    let protocols = matches
        .values_of("protocol")
        .map(|v| v.collect::<IndexSet<&str>>())
        .unwrap_or(indexset! {"basic"});

    #[cfg(feature = "quic")]
    let load_certs = || {
        Err(CliError::ArgumentError(
            "Relay quic protocol not implemented".to_string(),
        ))
    };

    for (index, protocol_str) in protocols.iter().enumerate() {
        let local_address = local_addresses.get_index(index).ok_or_else(|| {
            CliError::ArgumentError(format!(
                "bind-address index {} has not been provided",
                index
            ))
        })?;
        let socket_addresses: Vec<SocketAddr> = local_address
            .split(',')
            .map(|v| {
                v.parse::<SocketAddr>().map_err(|_| {
                    CliError::ArgumentError(format!("Invalid bind-address provided {}", v))
                })
            })
            .collect::<Result<Vec<SocketAddr>, CliError>>()?;

        let protocol = Protocol::from(
            Some(protocol_str),
            #[cfg(feature = "quic")]
            load_certs,
        )?;

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
            result
        }
        Err(err) => {
            error!("{}", err);
            Err(CliError::JoinError(err))
        }
    }
}
