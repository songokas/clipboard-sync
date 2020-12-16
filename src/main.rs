// #![feature(ip)]

use chacha20poly1305::Key;
use log::{error, info};
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
pub mod protocols;
pub mod socket;
pub mod test;

use crate::config::{load_default_certificates, load_groups, FullConfig};
use crate::defaults::*;
use crate::errors::CliError;
use crate::filesystem::read_file_to_string;
use crate::message::Group;
use crate::process::{wait_handle_receive, wait_on_clipboard};
use crate::socket::Protocol;

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
    let public_ip = matches.value_of("public-ip").map(|ip| ip.to_owned());

    let group = matches.value_of("group").unwrap_or(DEFAULT_GROUP);
    let clipboard_type = matches.value_of("clipboard").unwrap_or(DEFAULT_CLIPBOARD);

    let key_data: String = match matches.value_of("key") {
        Some(expected_key) => match read_file_to_string(expected_key, KEY_SIZE) {
            Ok(file_contents) => file_contents,
            Err(_) => expected_key.to_owned(),
        },
        None => "".to_owned(),
    };

    if config_path.is_none() && key_data.len() != KEY_SIZE {
        return Err(CliError::ArgumentError(format!(
            "Please provide a valid key with length {}. Current: {}",
            KEY_SIZE,
            key_data.len()
        )));
    }

    let default_host = match matches.value_of("protocol") {
        Some(v) if v == "basic" => DEFAULT_ALLOWED_HOST,
        _ => "",
    };

    let allowed_host = matches.value_of("allowed-host").unwrap_or(default_host);

    let create_groups_from_cli = || -> Result<FullConfig, CliError> {
        if allowed_host.is_empty() {
            return Err(CliError::ArgumentError(format!(
                "Please provide --allowed-host 192.168.0.5 or use basic protocol",
            )));
        }

        let send_using_address = send_address.parse::<SocketAddr>()?;

        let key = Key::from_slice(key_data.as_bytes());

        let socket_address = local_address.parse::<SocketAddr>()?;

        let groups = vec![Group {
            name: group.to_owned(),
            allowed_hosts: vec![allowed_host.to_owned()],
            key: key.clone(),
            public_ip: public_ip.clone(),
            send_using_address,
            clipboard: clipboard_type.to_owned(),
        }];
        let full_config = FullConfig::from_groups(
            socket_address,
            send_using_address,
            public_ip.clone(),
            groups,
        );
        Ok(full_config)
    };

    let create_groups_from_config = |config_path: &str| -> Result<FullConfig, CliError> {
        return load_groups(config_path, allowed_host);
    };

    let full_config = config_path
        .map(|config_path| create_groups_from_config(&config_path))
        .unwrap_or_else(create_groups_from_cli)?;

    let protocol = match matches.value_of("protocol") {
        #[cfg(feature = "quic")]
        Some(v) if v == "quic" => {
            if let Some(c) = &full_config.certificates {
                Protocol::Quic(c.clone())
            } else {
                Protocol::Quic(load_default_certificates(
                    matches.value_of("private-key"),
                    matches.value_of("public-key"),
                    matches.value_of("cert-verify-dir"),
                )?)
            }
        }
        #[cfg(feature = "frames")]
        Some(v) if v == "frames" => Protocol::Frames,
        Some(v) if v == "basic" => Protocol::Basic,
        Some(v) => {
            return Err(CliError::ArgumentError(format!(
                "Protocol {} is not available",
                v
            )));
        }
        None => Protocol::Basic,
    };

    let running = Arc::new(AtomicBool::new(true));

    let (tx, rx) = channel(MAX_CHANNEL);

    let receive = wait_handle_receive(
        tx,
        full_config.bind_address,
        Arc::clone(&running),
        full_config.clone(),
        protocol.clone(),
    );
    let send = wait_on_clipboard(
        rx,
        Arc::clone(&running),
        full_config.clone(),
        protocol.clone(),
    );

    let res = try_join!(tokio::spawn(receive), tokio::spawn(send),);
    match res {
        Ok((r, s)) => {
            info!("Finished running receive count {} sent count {}", r?, s?);
            return Ok(());
        }
        Err(err) => {
            error!("Finished with error {:?}", err);
            return Err(CliError::JoinError(err));
        }
    };
}
