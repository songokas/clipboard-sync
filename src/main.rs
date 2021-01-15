// #![feature(ip)]
#![allow(dead_code)]

use chacha20poly1305::Key;
use log::{error, info};
use std::sync::Arc;
use tokio::sync::mpsc::channel;

use clap::{load_yaml, App};
#[cfg(feature = "clipboard")]
use clipboard::ClipboardProvider;
use env_logger::Env;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;

mod channel_clipboard;
mod config;
mod defaults;
mod empty_clipboard;
mod encryption;
mod errors;
mod filesystem;
mod message;
mod process;
mod protocols;
mod socket;
mod test;

use crate::config::load_default_certificates;
use crate::config::{generate_config, load_groups, FullConfig};
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

    let config_path: Option<String> = match matches.value_of("config") {
        Some(p) => Some(p.to_owned()),
        None => {
            if matches.is_present("autogenerate") {
                match generate_config("clipboard-sync") {
                    Ok(p) => {
                        let path = p.to_string_lossy().to_string();
                        info!("Configuration autogeneration {}", path);
                        Some(path)
                    }
                    Err(e) => {
                        error!("Unable to generate config {:?}", e);
                        None
                    }
                }
            } else {
                None
            }
        }
    };

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
            "Please provide a valid key with length {}. Current: {}. clipboard-sync --help",
            KEY_SIZE,
            key_data.len()
        )));
    }

    let private_key = matches.value_of("private-key");
    let public_key = matches.value_of("public-key");
    let cert_dir = matches.value_of("cert-verify-dir");

    let load_certs = move || {
        return load_default_certificates(private_key, public_key, cert_dir);
    };

    let default_host = match matches.value_of("protocol") {
        Some(v) if v == "basic" => DEFAULT_ALLOWED_HOST,
        Some(_) => "",
        _ => DEFAULT_ALLOWED_HOST,
    };

    let allowed_host = matches.value_of("allowed-host").unwrap_or(default_host);

    let create_groups_from_cli = || -> Result<FullConfig, CliError> {
        let cli_protocol = Protocol::from(matches.value_of("protocol"), load_certs)?;

        if allowed_host.is_empty() {
            return Err(CliError::ArgumentError(format!(
                "Please provide --allowed-host or use basic protocol",
            )));
        }

        let send_using_address = send_address.parse::<SocketAddr>()
            .map_err(|_| CliError::ArgumentError(format!("Invalid send-using-address provided {}", send_address)))?;

        let key = Key::from_slice(key_data.as_bytes());

        let socket_address = local_address.parse::<SocketAddr>()
            .map_err(|_| CliError::ArgumentError(format!("Invalid bind address provided {}", local_address)))?;

        let groups = vec![Group {
            name: group.to_owned(),
            allowed_hosts: vec![allowed_host.to_owned()],
            key: key.clone(),
            public_ip: public_ip.clone(),
            send_using_address,
            clipboard: clipboard_type.to_owned(),
            protocol: cli_protocol.clone(),
        }];

        let full_config = FullConfig::from_protocol_groups(
            cli_protocol,
            socket_address,
            groups,
            MAX_RECEIVE_BUFFER,
            !matches.is_present("ignore-initial-clipboard"),
        );
        Ok(full_config)
    };

    let create_groups_from_config = |config_path: &str| -> Result<FullConfig, CliError> {
        return load_groups(
            config_path,
            allowed_host,
            load_certs,
            !matches.is_present("ignore-initial-clipboard"),
        );
    };

    let full_config = config_path
        .map(|config_path| create_groups_from_config(&config_path))
        .unwrap_or_else(create_groups_from_cli)?;

    let running = Arc::new(AtomicBool::new(true));

    let (tx, rx) = channel(MAX_CHANNEL);
    let atx = Arc::new(tx);

    let (stat_sender, _) = channel(MAX_CHANNEL);
    let stat_sender = Arc::new(stat_sender);

    let send_once = matches.is_present("send-once");
    let receive_once = matches.is_present("receive-once");
    let launch_receiver = receive_once || !send_once;
    let launch_sender = send_once || !receive_once;

    let mut handles = Vec::new();

    if launch_receiver {
        for (protocol, bind_address) in &full_config.bind_addresses {
            let clipboard = Clipboard::new().expect("Unable to initialize clipboard. Possibly missing xcb libraries");
            let receive = wait_handle_receive(
                clipboard,
                Arc::clone(&atx),
                bind_address.clone(),
                Arc::clone(&running),
                full_config.clone(),
                protocol.clone(),
                Arc::clone(&stat_sender),
                receive_once,
            );
            handles.push(tokio::spawn(receive));
        }
    }

    if launch_sender {
        let clipboard = Clipboard::new().expect("Unable to initialize clipboard. Possibly missing xcb libraries");
        let send = wait_on_clipboard(
            clipboard,
            rx,
            Arc::clone(&running),
            full_config.clone(),
            Arc::clone(&stat_sender),
            send_once,
        );
        handles.push(tokio::spawn(send));
    }

    let result = futures::future::try_join_all(handles).await;
    match result {
        Ok(items) => {
            for res in items {
                match res {
                    Ok(c) => {
                        info!("count {}", c);
                    }
                    Err(e) => {
                        error!("error: {:?}", e)
                    }
                }
            }
            return Ok(());
        }
        Err(err) => {
            error!("{}", err);
            return Err(CliError::JoinError(err));
        }
    };
}
