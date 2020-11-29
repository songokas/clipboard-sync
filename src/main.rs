#![feature(ip)]

use chacha20poly1305::Key;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc::channel;
use log::{debug};

use clap::{load_yaml, App};
use env_logger::Env;
use futures::join;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;

pub mod config;
pub mod encryption;
pub mod errors;
pub mod message;
pub mod process;

use crate::config::{load_groups, FullConfig};
use crate::errors::CliError;
use crate::message::Group;
use crate::process::{wait_on_clipboard, wait_on_receive};

const MAX_CHANNEL: usize = 100;
const KEY_SIZE: usize = 32;

#[tokio::main]
async fn main() -> Result<(), CliError>
{
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let verbosity = matches.value_of("verbose").unwrap_or("info");
    env_logger::from_env(Env::default().default_filter_or(verbosity)).init();

    let config_path = matches.value_of("config");

    let local_address = matches.value_of("bind-address").unwrap_or("0.0.0.0:8900");
    let send_address = matches.value_of("send-address").unwrap_or("0.0.0.0:8901");
    let public_ip = matches
        .value_of("public-ip")
        .and_then(|ip| ip.parse::<IpAddr>().ok());

    let group = matches.value_of("group").unwrap_or("default");

    let allowed_host = matches
        .value_of("allowed-host")
        .unwrap_or("224.0.0.89:8900");

    let key_data = matches.value_of("key").unwrap_or("");
    
    if config_path.is_none() {
        if key_data.len() != KEY_SIZE {
            return Err(CliError::ArgumentError(format!(
                "Please provide a valid key with length {}. Current: {}",
                KEY_SIZE,
                key_data.len()
            )));
        }
    }

    let create_groups_from_cli = || -> Result<FullConfig, CliError> {
        let allowed_host_addr = allowed_host.parse::<SocketAddr>()?;
        let send_using_address = send_address.parse::<SocketAddr>()?;
        let key = Key::from_slice(key_data.as_bytes());

        let socket_address = local_address
            .parse::<SocketAddr>()
            .map_err(|err| CliError::ArgumentError(err.to_string()))?;

        let groups = vec![Group {
            name: group.to_owned(),
            allowed_hosts: vec![allowed_host_addr],
            key: key.clone(),
            public_ip,
            send_using_address,
        }];
        let full_config =
            FullConfig::from_groups(socket_address, send_using_address, public_ip, groups);
        Ok(full_config)
    };

    let create_groups_from_config = |config_path: &str| -> Result<FullConfig, CliError> {
        let allowed_host_addr = allowed_host.parse::<SocketAddr>()?;
        return load_groups(config_path, allowed_host_addr);
    };

    let full_config = config_path
        .map(|config_path| create_groups_from_config(&config_path))
        .unwrap_or_else(create_groups_from_cli)?;

    debug!("{:?}", full_config);
    let running = Arc::new(AtomicBool::new(true));

    let (tx, rx) = channel(MAX_CHANNEL);
    let groups = full_config.groups();
    join!(
        wait_on_receive(
            tx,
            full_config.bind_address,
            Arc::clone(&running),
            &groups
        ),
        wait_on_clipboard(rx, Arc::clone(&running), &groups)
    );

    Ok(())
}

