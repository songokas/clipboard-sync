// #![feature(ip)]

use chacha20poly1305::Key;
use log::{error, info};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc::channel;

use clap::{load_yaml, App};
use env_logger::Env;
use futures::try_join;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;

pub mod config;
pub mod defaults;
pub mod encryption;
pub mod errors;
pub mod filesystem;
pub mod message;
pub mod process;
pub mod socket;
pub mod protocols;

use crate::config::{load_groups, FullConfig};
use crate::defaults::*;
use crate::errors::CliError;
use crate::filesystem::read_file_to_string;
use crate::message::Group;
use crate::process::{wait_on_clipboard, wait_on_receive};

#[tokio::main]
async fn main() -> Result<(), CliError>
{
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let verbosity = matches.value_of("verbose").unwrap_or("info");
    env_logger::from_env(Env::default().default_filter_or(verbosity)).init();

    let config_path = matches.value_of("config");

    let local_address = matches.value_of("bind-address").unwrap_or(BIND_ADDRESS);
    let send_address = matches
        .value_of("send-using-address")
        .unwrap_or(SEND_ADDRESS);
    let public_ip = matches
        .value_of("public-ip")
        .and_then(|ip| ip.parse::<IpAddr>().ok());

    let group = matches.value_of("group").unwrap_or(DEFAULT_GROUP);
    let clipboard_type = matches.value_of("clipboard").unwrap_or(DEFAULT_CLIPBOARD);

    let protocol = matches.value_of("protocol").unwrap_or(DEFAULT_PROTOCOL);
    let mut protocols = vec![];
    if cfg!(feature = "basic") {
        protocols.push("basic");
    }
    if cfg!(feature = "frames") {
        protocols.push("frames");
    }
    if cfg!(feature = "quic") {
        protocols.push("quic");
    }

    if !protocols.contains(&protocol) {
        return Err(CliError::ArgumentError(format!(
            "Protocol {} has not been compiled",
            protocol
        )));
    }

    let allowed_host = matches
        .value_of("allowed-host")
        .unwrap_or(DEFAULT_ALLOWED_HOST);

    let key_data: String = match matches.value_of("key") {
        Some(expected_key) => match read_file_to_string(expected_key, KEY_SIZE) {
            Ok(file_contents) => file_contents,
            Err(_) => expected_key.to_owned(),
        },
        None => "".to_owned(),
    };

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

        let socket_address = local_address.parse::<SocketAddr>()?;

        let groups = vec![Group {
            name: group.to_owned(),
            allowed_hosts: vec![allowed_host_addr],
            key: key.clone(),
            public_ip,
            send_using_address,
            clipboard: clipboard_type.to_owned(),
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

    let running = Arc::new(AtomicBool::new(true));

    let (tx, rx) = channel(MAX_CHANNEL);
    let groups = full_config.groups();
    let res = try_join!(
        wait_on_receive(
            tx,
            full_config.bind_address,
            Arc::clone(&running),
            &groups,
            protocol.to_owned()
        ),
        wait_on_clipboard(rx, Arc::clone(&running), &groups, protocol.to_owned())
    );
    match res {
        Ok(((), ())) => {
            info!("Finished running");
            return Ok(());
        }
        Err(err) => {
            error!("Finished with error {:?}", err);
            return Err(err);
        }
    };
}
