use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use clap::Parser;
// use clipboard_sync::pools::socket_pool::SocketPool;
use clipboard_sync::protocol::Protocol;
use core::time::Duration;
use indexmap::{indexset, IndexSet};
use std::convert::TryInto;
use std::net::SocketAddr;
use tokio::task::JoinSet;
use x25519_dalek::{PublicKey, StaticSecret};

use log::{error, info};

use env_logger::Env;

use clipboard_sync::config::RelayConfig;
use clipboard_sync::defaults::{BIND_ADDRESS, DEFAULT_RELAY_MESSAGE_SIZE, KEY_SIZE};
use clipboard_sync::encryption::random;
use clipboard_sync::errors::CliError;
use clipboard_sync::filesystem::read_file;
use clipboard_sync::relays::relay_packets;

const DEFAULT_MAX_GROUP_SIZE: u64 = 1000;
const DEFAULT_MAX_SOCKET_SIZE: u64 = 10;
const DEFAULT_MAX_GROUPS_PER_IP: u64 = 10;
const DEFAULT_SOCKET_KEEP_TIME: &str = "60";
const DEFAULT_VALID_FOR: &str = "300";
static BIND_ADDRESSES: &[&str] = &[BIND_ADDRESS, "0.0.0.0:8901", "0.0.0.0:8902"];

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CliConfig {
    #[arg(
        short,
        long,
        help = "set the level of logging verbosity",
        default_value = "info"
    )]
    pub verbosity: String,

    #[arg(long, help="address to listen on", default_value = BIND_ADDRESS)]
    pub bind_address: Vec<String>,

    #[arg(long, help = "use protocol")]
    pub protocol: Vec<Protocol>,

    #[arg(short='s', long, help="how many bytes to consider as message", default_value_t = DEFAULT_RELAY_MESSAGE_SIZE)]
    pub message_size: usize,

    #[arg(
        short = 'k',
        long,
        help = "encryption key 32 chars long default: automatically generated"
    )]
    pub private_key: Option<String>,

    #[arg(long, help = "how many groups can this server handle", default_value_t = DEFAULT_MAX_GROUP_SIZE)]
    pub max_groups: u64,

    #[arg(long, help = "how many sockets per group are allowed", default_value_t = DEFAULT_MAX_SOCKET_SIZE)]
    pub max_sockets: u64,

    #[arg(long, help="how many seconds sockets are kept for", value_parser = |s: &str| s.parse().map(Duration::from_secs), default_value = DEFAULT_SOCKET_KEEP_TIME)]
    pub keep_sockets_for: Duration,

    #[arg(long, help="how many seconds message is considered valid", value_parser = |s: &str| s.parse().map(Duration::from_secs),  default_value = DEFAULT_VALID_FOR)]
    pub valid_for: Duration,

    #[arg(long, help="how many groups are allowed per ip", default_value_t = DEFAULT_MAX_GROUPS_PER_IP)]
    pub max_per_ip: u64,
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    let cli_config = CliConfig::parse();
    let (verbosity, custom_format) = if let Some(v) = cli_config.verbosity.strip_suffix("=simple") {
        (v.to_string(), true)
    } else {
        (cli_config.verbosity.to_string(), false)
    };

    let mut builder = env_logger::Builder::from_env(Env::default().default_filter_or(verbosity));
    if custom_format {
        use std::io::Write;
        builder.format(|buf, record| writeln!(buf, "{}", record.args()));
    }
    builder.init();

    let private_key = cli_config
        .private_key
        .map(|s| {
            let key_data: Vec<u8> = match read_file(&s, KEY_SIZE) {
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

    info!(
        "Server public key {}",
        BASE64_STANDARD.encode(public.as_bytes())
    );

    let config = RelayConfig {
        max_groups: cli_config.max_groups,
        max_sockets: cli_config.max_sockets,
        message_size: cli_config.message_size,
        keep_sockets_for: cli_config.keep_sockets_for,
        private_key: private_key.to_bytes(),
        valid_for: cli_config.valid_for,
        max_per_ip: cli_config.max_per_ip,
    };

    let mut handles = JoinSet::new();

    // clipboard-relay --protocol tcp --bind-address 0.0.0.0:8901 --protocol basic --bind-address
    let local_addresses = if !cli_config.bind_address.is_empty() {
        cli_config
            .bind_address
            .iter()
            .map(|s| s.as_str())
            .collect::<IndexSet<&str>>()
    } else {
        BIND_ADDRESSES.iter().copied().collect::<IndexSet<&str>>()
    };
    let protocols = if !cli_config.protocol.is_empty() {
        cli_config
            .protocol
            .into_iter()
            .collect::<IndexSet<Protocol>>()
    } else {
        indexset! {Protocol::Basic}
    };

    for (index, protocol) in protocols.iter().enumerate() {
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

        for bind_address in socket_addresses {
            let receive = relay_packets(bind_address, *protocol, config.clone());
            handles.spawn(receive);
        }
    }

    let mut result = Ok(());

    let results = handles.join_all().await;
    for res in results {
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
