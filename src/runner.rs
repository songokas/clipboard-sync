#![allow(dead_code)]

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use bytes::Bytes;
use chacha20poly1305::Key;
use core::time::Duration;
use indexmap::indexset;
use indexmap::{indexmap, IndexSet};
use log::debug;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use x25519_dalek::PublicKey;

use crate::clipboards::ClipboardReadMessage;
use crate::config::FullConfig;
use crate::config::UserCertificates;
use crate::defaults::{get_default_hosts, ExecutorResult, CLIPBOARD_NAME};
use crate::defaults::{KEY_SIZE, MESSAGE_VALID_DURATION};
use crate::defaults::{MAX_CHANNEL, RECEIVE_ONCE_WAIT};
use crate::encryption::random;
use crate::errors::CliError;
use crate::errors::ConnectionError;
use crate::executors::receiver_protocol_executors;
use crate::executors::sender_protocol_executors;
use crate::message::AllowedHosts;
use crate::message::GroupName;
use crate::message::MessageType;
use crate::message::{Group, Relay};
use crate::pools::PoolFactory;
use crate::protocol::Protocol;
use crate::protocols::ProtocolReadMessage;
use crate::protocols::StatusMessage;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AndroidRelay {
    host: String,
    public_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct AndroidConfig {
    key: Option<String>,
    group: GroupName,
    protocol: Protocol,
    hosts: AllowedHosts,
    send_using_address: IndexSet<SocketAddr>,
    bind_address: IndexSet<SocketAddr>,
    visible_ip: Option<String>,
    heartbeat: Option<u64>,
    relay: Option<AndroidRelay>,
    private_key: Option<String>,
    certificate_chain: Option<String>,
    remote_certificates: Option<String>,
    app_dir: PathBuf,
    max_receive_size: usize,
    max_file_size: usize,
    #[serde(default)]
    danger_client_no_verify: bool,
    #[serde(default)]
    danger_server_no_verify: bool,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct StatusCount {
    pub sent: u64,
    pub received: u64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct StatusInfo {
    pub status_count: StatusCount,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Status {
    pub state: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_count: Option<StatusCount>,
}

impl From<Result<(), String>> for Status {
    fn from(result: Result<(), String>) -> Self {
        match result {
            Ok(_) => Status {
                state: true,
                error: None,
                status_count: None,
            },
            Err(error) => Status {
                state: false,
                error: error.into(),
                status_count: None,
            },
        }
    }
}

impl From<bool> for Status {
    fn from(state: bool) -> Self {
        Status {
            state,
            error: None,
            status_count: None,
        }
    }
}

impl From<Option<StatusInfo>> for Status {
    fn from(status_info: Option<StatusInfo>) -> Self {
        if let Some(StatusInfo {
            status_count,
            error,
        }) = status_info
        {
            Status {
                state: true,
                error,
                status_count: status_count.into(),
            }
        } else {
            Status {
                state: false,
                error: None,
                status_count: None,
            }
        }
    }
}

pub fn create_config(
    config_str: String,
) -> Result<(FullConfig, Option<UserCertificates>, bool), String> {
    debug!("Start with config {}", config_str);

    let mut config: AndroidConfig = match serde_json::from_str(&config_str) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to parse config {}", e)),
    };

    let key_required = matches!(config.protocol, Protocol::Basic | Protocol::Tcp);

    if config
        .key
        .as_ref()
        .map(|s| s.len() != KEY_SIZE)
        .unwrap_or(key_required)
    {
        return Err(format!(
            "Please provide a valid key with length {} for {} protocol. Current: {}",
            KEY_SIZE,
            config.protocol,
            config.key.map(|s| s.len()).unwrap_or(0),
        ));
    }
    if config.group.is_empty() {
        return Err("Please provide any group name".into());
    }
    if config.hosts.is_empty() {
        config.hosts = get_default_hosts(config.protocol);
    }
    if config.send_using_address.is_empty() {
        return Err("Please provide socket send address".into());
    }
    if config.bind_address.is_empty() {
        return Err("Please provide socket bind address".into());
    }

    let key = config
        .key
        .map(|s| Key::clone_from_slice(s.as_bytes()))
        .unwrap_or_else(|| *Key::from_slice(&random(KEY_SIZE)));

    let send_using_address = config.send_using_address;
    let socket_address = config.bind_address;

    let user_certificates = if let (Some(private_key), Some(certificate_chain)) =
        (config.private_key, config.certificate_chain)
    {
        UserCertificates {
            private_key,
            certificate_chain,
            remote_certificates: config.remote_certificates,
            subject: None,
        }
        .into()
    } else {
        None
    };

    let relay = if let Some(r) = config.relay {
        let decoded = BASE64_STANDARD
            .decode(&r.public_key)
            .map_err(|e| format!("Invalid relay public key provided: {}", e))?;
        let key: [u8; KEY_SIZE] = decoded
            .try_into()
            .map_err(|_| "Invalid relay public key length".to_string())?;
        let public_key = PublicKey::from(key);
        Some(Relay {
            host: r.host,
            public_key,
        })
    } else {
        None
    };

    let group = Group {
        name: config.group.clone(),
        allowed_hosts: config.hosts,
        key,
        visible_ip: config.visible_ip,
        send_using_address,
        clipboard: CLIPBOARD_NAME.into(),
        protocol: config.protocol,
        heartbeat: if config.heartbeat > Some(0) {
            config.heartbeat.map(Duration::from_secs)
        } else {
            None
        },
        message_valid_for: MESSAGE_VALID_DURATION.into(),
        relay,
    };
    let groups = indexmap! { config.group => group };
    let full_config = FullConfig::from_protocol_groups(
        config.protocol,
        socket_address,
        groups,
        config.max_receive_size,
        config.max_file_size,
        RECEIVE_ONCE_WAIT,
        true,
        None,
        Some(config.app_dir),
        !config.danger_client_no_verify,
    );

    Ok((
        full_config,
        user_certificates,
        config.danger_server_no_verify,
    ))
}

pub async fn create_runner(config_str: String) -> Result<Runner, String> {
    let (full_config, user_certificates, danger_server_no_verify) = create_config(config_str)?;
    let runner = Runner::start(full_config, user_certificates, danger_server_no_verify).await?;
    Ok(runner)
}

pub struct Runner {
    handles: JoinSet<ExecutorResult>,
    stats: Receiver<StatusMessage>,
    queue_sender: Sender<ClipboardReadMessage>,
    queue_receiver: Receiver<ProtocolReadMessage>,
    received_count: u64,
    sent_count: u64,
    group_name: GroupName,
    cancel: CancellationToken,
    config: FullConfig,
}

impl Runner {
    pub fn status(&mut self) -> StatusInfo {
        let mut error = None;
        while let Ok(m) = self.stats.try_recv() {
            match m {
                StatusMessage::Ok(_) => self.sent_count += 1,
                StatusMessage::Err(e) => error = e.into(),
            }
        }
        if let Some(r) = self.handles.try_join_next() {
            match r {
                Ok(Err(e)) => error = e.to_string().into(),
                Err(e) => error = e.to_string().into(),
                _ => (),
            }
        }
        StatusInfo {
            status_count: StatusCount {
                sent: self.sent_count,
                received: self.received_count,
            },
            error,
        }
    }

    pub fn receive(&mut self) -> Option<(ProtocolReadMessage, usize, PathBuf)> {
        let message = self.queue_receiver.try_recv().ok()?;
        // accept only public keys when client auth is disabled
        if !self.config.tls_client_auth && message.message_type != MessageType::PublicKey {
            debug!(
                "Ignoring message since client auth is disabled remote_addr={} message_type={}",
                message.remote, message.message_type
            );
            return None;
        }
        self.received_count += 1;
        Some((
            message,
            self.config.max_file_size,
            self.config
                .app_dir
                .clone()
                .expect("App dir must be provided"),
        ))
    }

    pub fn queue(&mut self, data: Bytes, message_type: MessageType) -> Result<(), String> {
        debug!("Queue message_type={message_type} data_size={}", data.len());
        self.queue_sender
            .try_send(ClipboardReadMessage {
                groups: indexset! { self.group_name.clone() },
                message_type,
                data,
            })
            .map_err(|e| format!("Unable to queue contents {}", e))
    }

    pub async fn stop(self) -> Result<(), CliError> {
        debug!("Stopping runner");
        self.cancel.cancel();
        // self.handles.abort_all();
        Ok(())
    }

    pub async fn start(
        full_config: FullConfig,
        user_certificates: Option<UserCertificates>,
        danger_server_no_verify: bool,
    ) -> Result<Self, String> {
        debug!("Starting runner");

        let (stat_sender, stat_receiver) = channel(MAX_CHANNEL);

        let load_server_certs = move || {
            if let Some(certs) = user_certificates.clone() {
                Ok(certs.try_into()?)
            } else {
                Err(ConnectionError::BadConfiguration(
                    "No certificates provided".to_string(),
                ))
            }
        };
        let server_load = load_server_certs.clone();
        let load_client_certs = move || {
            let result = server_load();
            if danger_server_no_verify {
                Ok(result.ok())
            } else {
                result.map(Some)
            }
        };

        let pools = PoolFactory::default();
        let cancel = CancellationToken::new();
        let (protocol_received_sender, protocol_receiver) = channel(MAX_CHANNEL);
        let mut handles = JoinSet::new();
        receiver_protocol_executors(
            &mut handles,
            protocol_received_sender,
            pools.clone(),
            cancel.clone(),
            &full_config,
            load_server_certs,
        );

        let clipboard_received_sender = sender_protocol_executors(
            &mut handles,
            stat_sender,
            &full_config,
            pools,
            load_client_certs,
        );

        Ok(Runner {
            handles,
            stats: stat_receiver,
            queue_sender: clipboard_received_sender,
            queue_receiver: protocol_receiver,
            received_count: 0,
            sent_count: 0,
            group_name: full_config
                .groups
                .first()
                .map(|(k, _)| k.clone())
                .expect("At least one group"),
            cancel,
            config: full_config,
        })
    }
}
