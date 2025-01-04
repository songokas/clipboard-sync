use crate::encryption::random;
use crate::protocol::Protocol;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use chacha20poly1305::Key;
use log::{error, info};

use indexmap::{indexmap, IndexSet};
use std::convert::TryInto;
use std::net::SocketAddr;
use std::path::PathBuf;
use x25519_dalek::PublicKey;

use crate::config::{create_groups_from_config_file, generate_config, get_app_dir, FullConfig};
use crate::config::{CliConfig, FileCertificates};
use crate::defaults::*;
use crate::errors::CliError;
use crate::filesystem::read_file_to_string;
use crate::message::{AllowedHosts, Group, Relay};
use crate::socket::ipv6_support;

pub fn load_configuration(
    cli_config: CliConfig,
) -> Result<(FullConfig, Option<FileCertificates>), CliError> {
    let key_data: Option<String> = match cli_config.key.clone() {
        Some(expected_key) => match read_file_to_string(&expected_key, KEY_SIZE) {
            Ok((file_contents, _)) => file_contents.into(),
            Err(_) => expected_key.into(),
        },
        None => None,
    };

    let config_path: Option<PathBuf> = match cli_config.config.clone() {
        Some(p) => Some(p),
        None => {
            if cli_config.autogenerate || key_data.is_none() {
                match generate_config(get_app_dir(cli_config.app_dir.clone())?) {
                    Ok((path, gen)) => {
                        if gen {
                            info!("Configuration auto generation {}", path.to_string_lossy());
                        }
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
    // let default_allowed_host = cli_config
    //     .allowed_host
    //     .clone()
    //     .or_else(|| DEFAULT_ALLOWED_HOST.to_string().into());
    let cli_allowed_hosts: Option<AllowedHosts> = cli_config.allowed_host.as_deref().map(|s| {
        s.split(',')
            .filter(|s| !s.is_empty())
            .map(|h| {
                h.split_once('=')
                    .map(|(s, d)| (s.into(), Some(d.into())))
                    .unwrap_or((h.into(), None))
            })
            .collect()
    });

    let send_address = cli_config.send_using_address.clone().unwrap_or({
        let supports_ipv6_sockets = ipv6_support();
        if supports_ipv6_sockets {
            SEND_ADDRESS_IPV6.to_string()
        } else {
            SEND_ADDRESS.to_string()
        }
    });

    if config_path.is_none()
        && matches!(cli_config.protocol, Protocol::Basic | Protocol::Tcp)
        && key_data.as_ref().map(|d| d.len()) != Some(KEY_SIZE)
    {
        return Err(CliError::ArgumentError(format!(
            "Please provide a valid key with length {}. Current: {}. clipboard-sync --help",
            KEY_SIZE,
            key_data.unwrap_or_default().len()
        )));
    }

    let relay_public_key = cli_config.relay_public_key.as_ref().and_then(|s| {
        let key: Option<[u8; KEY_SIZE]> = match BASE64_STANDARD.decode(s) {
            Ok(d) => d.try_into().ok(),
            Err(_) => None,
        };
        key.map(PublicKey::from)
    });

    let relay_config = match &cli_config.relay_host {
        Some(host) => match relay_public_key {
            Some(public_key) => Some(Relay {
                host: host.clone(),
                public_key,
            }),
            None => {
                return Err(CliError::ArgumentError(
                    "Please provide a valid base64 encoded relay servers public key".into(),
                ))
            }
        },
        None => None,
    };

    let default_key = if let Some(key_data) = key_data {
        *Key::from_slice(key_data.as_bytes())
    } else {
        *Key::from_slice(&random(KEY_SIZE))
    };

    if let Some(path) = config_path {
        create_groups_from_config_file(
            &path,
            cli_config,
            default_key,
            cli_allowed_hosts,
            send_address,
            relay_config,
        )
    } else {
        Ok((
            create_groups_from_cli(
                cli_config,
                default_key,
                cli_allowed_hosts,
                send_address,
                relay_config,
            )?,
            None,
        ))
    }
}

fn create_groups_from_cli(
    cli_config: CliConfig,
    key: Key,
    cli_allowed_hosts: Option<AllowedHosts>,
    send_address: String,
    relay: Option<Relay>,
) -> Result<FullConfig, CliError> {
    let allowed_hosts = cli_allowed_hosts.unwrap_or_else(|| get_default_hosts(cli_config.protocol));

    let send_using_address: IndexSet<SocketAddr> = send_address
        .split(',')
        .map(|v| {
            v.parse::<SocketAddr>().map_err(|_| {
                CliError::ArgumentError(format!("Invalid send-using-address provided {}", v))
            })
        })
        .collect::<Result<IndexSet<SocketAddr>, CliError>>()?;

    let socket_addresses: IndexSet<SocketAddr> = cli_config
        .bind_address
        .split(',')
        .map(|v| {
            v.parse::<SocketAddr>().map_err(|_| {
                CliError::ArgumentError(format!("Invalid bind-address provided {}", v))
            })
        })
        .collect::<Result<IndexSet<SocketAddr>, CliError>>()?;

    let groups = indexmap! {
        cli_config.group.clone() => Group {
            name: cli_config.group,
            allowed_hosts,
            key,
            visible_ip: cli_config.visible_ip,
            send_using_address,
            clipboard: if cli_config.clipboard == DEFAULT_CLIPBOARD { CLIPBOARD_NAME.to_string() } else { cli_config.clipboard },
            protocol: cli_config.protocol,
            heartbeat: cli_config.heartbeat.and_then(|s| (!s.is_zero()).then_some(s)),
            message_valid_for: (!cli_config.message_valid_for.is_zero()).then_some(cli_config.message_valid_for),
            relay,
        },
    };

    let full_config = FullConfig::from_protocol_groups(
        cli_config.protocol,
        socket_addresses,
        groups,
        cli_config.max_receive_buffer,
        cli_config.max_file_size,
        cli_config.receive_once_wait,
        !cli_config.ignore_initial_clipboard,
        cli_config.ntp_server,
        cli_config.app_dir,
        !cli_config.danger_client_no_verify,
    );
    Ok(full_config)
}
