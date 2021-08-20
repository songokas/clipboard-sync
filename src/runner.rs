#![allow(dead_code)]

use flume::Receiver;
#[cfg(target_os = "android")]
use flume::Sender;
use indexmap::{indexmap, IndexSet};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;
use x25519_dalek::PublicKey;

use chacha20poly1305::Key;
use futures::try_join;
use log::{debug, error, info};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

#[cfg(target_os = "android")]
use crate::clipboards::channel_clipboard::ChannelClipboardContext;
use crate::clipboards::Clipboard;
use crate::config::FullConfig;
use crate::defaults::{
    DEFAULT_CLIPBOARD, KEY_SIZE, MAX_CHANNEL, MAX_FILE_SIZE, MAX_RECEIVE_BUFFER, RECEIVE_ONCE_WAIT,
};
use crate::errors::CliError;
use crate::message::MessageType;
use crate::message::{Group, Relay};
use crate::process::{receive_clipboard, send_clipboard};
use crate::protocols::{Protocol, SocketPool};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AndroidRelay
{
    host: String,
    public_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct AndroidConfig
{
    key: String,
    group: String,
    protocol: String,
    hosts: IndexSet<String>,
    send_using_address: IndexSet<SocketAddr>,
    bind_address: IndexSet<SocketAddr>,
    visible_ip: Option<String>,
    heartbeat: u64,
    relay: Option<AndroidRelay>,
    app_dir: String,
}

#[derive(Debug, PartialEq)]
pub struct StatusCount
{
    pub sent: u64,
    pub received: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Status
{
    state: bool,
    message: String,
}

impl From<StatusCount> for Status
{
    fn from(status_count: StatusCount) -> Self
    {
        Self {
            state: true,
            message: format!(
                "received: {} sent: {}",
                status_count.received, status_count.sent
            ),
        }
    }
}

impl Status
{
    pub fn on(s: String) -> Self
    {
        Status {
            state: true,
            message: s,
        }
    }

    pub fn off(s: String) -> Self
    {
        Status {
            state: false,
            message: s,
        }
    }
}

impl From<Result<String, String>> for Status
{
    fn from(result: Result<String, String>) -> Self
    {
        match result {
            Ok(s) => Status::on(s),
            Err(e) => Status::off(e),
        }
    }
}

pub fn create_config(config_str: String) -> Result<FullConfig, String>
{
    debug!("Start with config {}", config_str);

    let config: AndroidConfig = match serde_json::from_str(&config_str) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to parse config {}", e)),
    };

    if config.key.len() != KEY_SIZE {
        return Err(format!(
            "Please provide a valid key with length {}. Current: {}",
            KEY_SIZE,
            config.key.len()
        ));
    }
    if config.group.is_empty() {
        return Err("Please provide any group name".into());
    }
    if config.hosts.is_empty() {
        return Err("Please provide host where to send clipboard".into());
    }
    if config.send_using_address.is_empty() {
        return Err("Please provide socket send address".into());
    }
    if config.bind_address.is_empty() {
        return Err("Please provide socket bind address".into());
    }

    let key = Key::clone_from_slice(config.key.as_bytes());

    let send_using_address = config.send_using_address;
    let socket_address = config.bind_address;

    let protocol = Protocol::from(
        Some(&config.protocol),
        #[cfg(feature = "quic")]
        || Err(CliError::ArgumentError("Android no certs".to_owned())),
    )
    .map_err(|e| e.to_string())?;

    let relay = if let Some(r) = config.relay {
        let decoded = base64::decode(&r.public_key)
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
        clipboard: String::from(DEFAULT_CLIPBOARD),
        protocol: protocol.clone(),
        heartbeat: config.heartbeat,
        message_valid_for: 180,
        relay,
    };
    let groups = indexmap! { config.group => group };
    let full_config = FullConfig::from_protocol_groups(
        protocol,
        socket_address,
        groups,
        MAX_RECEIVE_BUFFER,
        MAX_FILE_SIZE,
        RECEIVE_ONCE_WAIT,
        true,
        None,
        Some(config.app_dir),
    );

    Ok(full_config)
}

pub async fn create_runner(config_str: String) -> Result<(Runner, String), String>
{
    let full_config = create_config(config_str)?;
    let runner = Runner::start(full_config).await?;
    Ok((runner, String::from("Started")))
}

pub struct Runner
{
    sender: JoinHandle<Result<(String, u64), CliError>>,
    receiver: JoinHandle<Result<(String, u64), CliError>>,
    running: Arc<AtomicBool>,
    stats: Receiver<(u64, u64)>,
    #[cfg(target_os = "android")]
    queue_sender: Arc<Sender<(Vec<u8>, MessageType)>>,
    #[cfg(target_os = "android")]
    queue_receiver: Receiver<(Vec<u8>, MessageType)>,
    received_count: u64,
    sent_count: u64,
    pool: Arc<SocketPool>,
}

impl Runner
{
    pub fn status(&mut self) -> StatusCount
    {
        while let Ok((sent, received)) = self.stats.try_recv() {
            if received > 0 {
                self.received_count = received;
            }
            if sent > 0 {
                self.sent_count = sent;
            }
        }
        StatusCount {
            sent: self.sent_count,
            received: self.received_count,
        }
    }

    pub fn receive(&mut self) -> Option<(Vec<u8>, MessageType)>
    {
        #[cfg(not(target_os = "android"))]
        return None;
        #[cfg(target_os = "android")]
        return self.queue_receiver.try_recv().ok();
    }

    #[cfg(target_os = "android")]
    pub fn queue(&mut self, contents: Vec<u8>, message_type: MessageType) -> Result<(), String>
    {
        return self
            .queue_sender
            .try_send((contents, message_type))
            .map_err(|e| format!("Unable to queue contents {}", e));
    }

    pub async fn stop(self) -> Result<String, CliError>
    {
        debug!("Stopping runner");

        self.running.store(false, Ordering::Relaxed);
        let res = try_join!(self.receiver, self.sender);
        match res {
            Ok((receive_result, send_result)) => {
                let reiceive_message = match receive_result {
                    Ok((_, c)) => format!("receive count {}", c),
                    Err(e) => format!("receive error: {}", e),
                };

                let send_message = match send_result {
                    Ok((_, c)) => format!("send count {}", c),
                    Err(e) => format!("send error: {}", e),
                };
                let result = format!("Finished running. {} {}", reiceive_message, send_message);
                info!("{}", result);
                Ok(result)
            }
            Err(err) => {
                error!("{}", err);
                Err(CliError::JoinError(err))
            }
        }
    }

    pub async fn start(full_config: FullConfig) -> Result<Self, String>
    {
        debug!("Starting runner");

        let running = Arc::new(AtomicBool::new(true));

        let (tx, rx) = flume::bounded(MAX_CHANNEL);
        let (stat_sender, stat_receiver) = flume::bounded(MAX_CHANNEL);

        #[cfg(target_os = "android")]
        let mut clipboard_receive: Clipboard =
            ChannelClipboardContext::new().map_err(|_| "Expecting ChannelClipboardContext")?;
        #[cfg(not(target_os = "android"))]
        let clipboard_receive: Clipboard =
            Clipboard::new().map_err(|_| "Expecting ChannelClipboardContext")?;

        #[cfg(target_os = "android")]
        let clipboard_send: Clipboard =
            ChannelClipboardContext::new().map_err(|_| "Expecting ChannelClipboardContext")?;
        #[cfg(not(target_os = "android"))]
        let clipboard_send: Clipboard =
            Clipboard::new().map_err(|_| "Expecting ChannelClipboardContext")?;

        #[cfg(target_os = "android")]
        let queue_sender = clipboard_send.get_sender();
        #[cfg(target_os = "android")]
        let queue_receiver = clipboard_receive
            .get_receiver()
            .ok_or("Unable to obtain receiver")?;

        // @TODO add support for multiple bind addresses
        let (protocol, bind_address) = full_config
            .get_first_bind_address()
            .ok_or("Protocol bind addresses required")?;
        let pool = Arc::new(SocketPool::default());
        let receive = receive_clipboard(
            Arc::clone(&pool),
            clipboard_receive,
            tx,
            bind_address,
            Arc::clone(&running),
            full_config.clone(),
            protocol,
            stat_sender.clone(),
            false,
        );

        let send = send_clipboard(
            Arc::clone(&pool),
            clipboard_send,
            rx,
            Arc::clone(&running),
            full_config,
            stat_sender,
            false,
        );

        Ok(Runner {
            running,
            receiver: tokio::spawn(receive),
            sender: tokio::spawn(send),
            stats: stat_receiver,
            #[cfg(target_os = "android")]
            queue_sender,
            #[cfg(target_os = "android")]
            queue_receiver,
            received_count: 0,
            sent_count: 0,
            pool,
        })
    }
}
