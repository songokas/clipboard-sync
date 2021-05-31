// #![feature(ip)]
#![allow(dead_code)]
// #![feature(trait_alias)]
// #![feature(type_alias_impl_trait)]

use chacha20poly1305::Key;
#[cfg(feature = "ntp")]
use log::warn;
use log::{error, info};
use std::sync::Arc;

use clap::{load_yaml, App};
use env_logger::Env;
// use std::collections::HashSet;
use indexmap::{indexmap, IndexSet};
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
// use std::io::Write;

mod clipboards;
mod config;
mod defaults;
mod encryption;
mod errors;
mod filesystem;
mod fragmenter;
mod identity;
mod message;
mod multicast;
mod notify;
mod process;
mod protocols;
mod socket;
mod test;
mod time;

use crate::clipboards::Clipboard;
#[cfg(feature = "quic")]
use crate::config::load_default_certificates;
use crate::config::{generate_config, load_groups, FullConfig};
use crate::defaults::*;
use crate::errors::CliError;
use crate::filesystem::read_file_to_string;
use crate::message::Group;
use crate::process::{receive_clipboard, send_clipboard};
use crate::protocols::{Protocol, SocketPool};
use crate::socket::ipv6_support;
#[cfg(feature = "ntp")]
use crate::time::update_time_diff;

#[tokio::main]
async fn main() -> Result<(), CliError>
{
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let verbosity = matches.value_of("verbosity").unwrap_or("info");

    env_logger::Builder::from_env(Env::default().default_filter_or(verbosity)).init();

    let key_data: String = match matches.value_of("key") {
        Some(expected_key) => match read_file_to_string(expected_key, KEY_SIZE) {
            Ok((file_contents, _)) => file_contents,
            Err(_) => expected_key.to_owned(),
        },
        None => "".to_owned(),
    };

    let config_path: Option<String> = match matches.value_of("config") {
        Some(p) => Some(p.to_owned()),
        None => {
            if matches.is_present("autogenerate") || key_data == "" {
                match generate_config("clipboard-sync") {
                    Ok(p) => {
                        let path = p.to_string_lossy().to_string();
                        info!("Configuration autogeneration {}", path);
                        Some(path)
                    }
                    Err(e) => {
                        error!("Unable to generate config {}", e);
                        None
                    }
                }
            } else {
                None
            }
        }
    };

    let (supports_ipv6_sockets, _ipv6_only) = ipv6_support();

    let system_default_host = || DEFAULT_ALLOWED_HOST;

    let default_host = match matches.value_of("protocol") {
        Some(v) if v == Protocol::Basic.to_string() => system_default_host(),
        Some(_) => "",
        _ => system_default_host(),
    };

    let allowed_host = matches.value_of("allowed-host").unwrap_or(default_host);

    let local_address = matches
        .value_of("bind-address")
        .unwrap_or_else(|| BIND_ADDRESS);

    let send_address = matches.value_of("send-using-address").unwrap_or_else(|| {
        if supports_ipv6_sockets {
            SEND_ADDRESS_IPV6
        } else {
            SEND_ADDRESS
        }
    });
    let visible_ip = matches.value_of("visible-ip").map(|ip| ip.to_owned());

    let group = matches.value_of("group").unwrap_or(DEFAULT_GROUP);
    let clipboard_type = matches.value_of("clipboard").unwrap_or(DEFAULT_CLIPBOARD);

    if config_path.is_none() && key_data.len() != KEY_SIZE {
        return Err(CliError::ArgumentError(format!(
            "Please provide a valid key with length {}. Current: {}. clipboard-sync --help",
            KEY_SIZE,
            key_data.len()
        )));
    }
    #[cfg(feature = "quic")]
    let private_key = matches.value_of("private-key");
    #[cfg(feature = "quic")]
    let public_key = matches.value_of("public-key");
    #[cfg(feature = "quic")]
    let cert_dir = matches.value_of("cert-verify-dir");

    #[cfg(feature = "quic")]
    let load_certs = move || {
        return load_default_certificates(private_key, public_key, cert_dir);
    };

    let heartbeat = matches
        .value_of("heartbeat")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let message_valid_for = matches
        .value_of("message-valid-for")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(MESSAGE_VALID_TIME);
    let ntp_server = matches.value_of("ntp-server").unwrap_or(NTP_SERVER);

    let max_receive_buffer = matches
        .value_of("max-receive-buffer")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(MAX_RECEIVE_BUFFER);
    let max_file_size = matches
        .value_of("max-file-size")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(MAX_FILE_SIZE);

    let create_groups_from_cli = || -> Result<FullConfig, CliError> {
        let cli_protocol = Protocol::from(
            matches.value_of("protocol"),
            #[cfg(feature = "quic")]
            load_certs,
        )?;

        if allowed_host.is_empty() {
            return Err(CliError::ArgumentError(format!(
                "Please provide --allowed-host or use basic protocol for multicast support",
            )));
        }

        let send_using_address: IndexSet<SocketAddr> = send_address
            .split(",")
            .map(|v| {
                v.parse::<SocketAddr>().map_err(|_| {
                    CliError::ArgumentError(format!("Invalid send-using-address provided {}", v))
                })
            })
            .collect::<Result<IndexSet<SocketAddr>, CliError>>()?;

        let key = Key::from_slice(key_data.as_bytes());

        let socket_addresses: IndexSet<SocketAddr> = local_address
            .split(",")
            .map(|v| {
                v.parse::<SocketAddr>().map_err(|_| {
                    CliError::ArgumentError(format!("Invalid bind-address provided {}", v))
                })
            })
            .collect::<Result<IndexSet<SocketAddr>, CliError>>()?;

        let groups = indexmap! {
            group.to_owned() => Group {
                name: group.to_owned(),
                allowed_hosts: allowed_host.split(",").map(String::from).collect(),
                key: key.clone(),
                visible_ip: visible_ip.clone(),
                send_using_address,
                clipboard: clipboard_type.to_owned(),
                protocol: cli_protocol.clone(),
                heartbeat,
                message_valid_for,
            },
        };

        let full_config = FullConfig::from_protocol_groups(
            cli_protocol,
            socket_addresses,
            groups,
            max_receive_buffer,
            max_file_size,
            matches
                .value_of("receive-once-wait")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(RECEIVE_ONCE_WAIT),
            !matches.is_present("ignore-initial-clipboard"),
            Some(ntp_server.to_owned()),
        );
        Ok(full_config)
    };

    let create_groups_from_config = |config_path: &str| -> Result<FullConfig, CliError> {
        return load_groups(
            config_path,
            if allowed_host.is_empty() {
                system_default_host()
            } else {
                allowed_host
            },
            local_address,
            send_address,
            matches.value_of("protocol"),
            #[cfg(feature = "quic")]
            load_certs,
            !matches.is_present("ignore-initial-clipboard"),
            visible_ip.clone(),
            key_data.clone(),
            message_valid_for,
            ntp_server,
            max_receive_buffer,
            max_file_size,
            clipboard_type,
        );
    };

    let full_config = config_path
        .map(|config_path| create_groups_from_config(&config_path))
        .unwrap_or_else(create_groups_from_cli)?;

    let running = Arc::new(AtomicBool::new(true));

    let (tx, rx) = flume::bounded(MAX_CHANNEL);
    let (stat_sender, _) = flume::bounded(MAX_CHANNEL);

    let send_once = matches.is_present("send-once");
    let receive_once = matches.is_present("receive-once");
    let launch_receiver = receive_once || !send_once;
    let launch_sender = send_once || !receive_once;

    let mut handles = Vec::new();
    let pool = Arc::new(SocketPool::new());

    #[cfg(feature = "ntp")]
    match &full_config.ntp_server {
        Some(s) if s.len() > 0 => {
            handles.push(tokio::spawn(update_time_diff(running.clone(), s.clone())));
        }
        _ => warn!("Ntp server not provided"),
    };

    if launch_receiver {
        for (protocol, bind_address) in full_config.get_bind_adresses() {
            let clipboard = Clipboard::new().expect(
                "Unable to initialize clipboard. Possibly missing xcb libraries or no x server",
            );
            let receive = receive_clipboard(
                Arc::clone(&pool),
                clipboard,
                tx.clone(),
                bind_address,
                Arc::clone(&running),
                full_config.clone(),
                protocol,
                stat_sender.clone(),
                receive_once,
            );

            handles.push(tokio::spawn(receive));
        }
    }

    if launch_sender {
        let clipboard = Clipboard::new().expect(
            "Unable to initialize clipboard. Possibly missing xcb libraries or no x server",
        );
        let send = send_clipboard(
            Arc::clone(&pool),
            clipboard,
            rx,
            Arc::clone(&running),
            full_config.clone(),
            stat_sender,
            send_once,
        );
        handles.push(tokio::spawn(send));
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
