#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(target_os = "android")]
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{channel, Receiver};
use tokio::task::JoinHandle;

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
    default_socket_send_address, BIND_ADDRESS, DEFAULT_CLIPBOARD, KEY_SIZE, MAX_CHANNEL,
    MAX_RECEIVE_BUFFER, RECEIVE_ONCE_WAIT,
};
use crate::errors::CliError;
use crate::message::Group;
use crate::process::{wait_handle_receive, wait_on_clipboard};
use crate::socket::Protocol;

#[derive(Serialize, Deserialize)]
pub struct AndroidConfig
{
    key: String,
    group: String,
    protocol: String,
    hosts: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Status
{
    state: bool,
    message: String,
    clipboard: String,
}

#[derive(Debug, PartialEq)]
pub struct StatusCount
{
    pub sent: u64,
    pub received: u64,
    pub clipboard: String,
}

impl Status
{
    pub fn on(s: String, clipboard: String) -> Self
    {
        return Status {
            state: true,
            message: s,
            clipboard,
        };
    }

    pub fn off(s: String) -> Self
    {
        return Status {
            state: false,
            message: s,
            clipboard: String::from(""),
        };
    }
}

impl From<Result<String, String>> for Status
{
    fn from(result: Result<String, String>) -> Self
    {
        match result {
            Ok(s) => Status::on(s, String::from("")),
            Err(e) => Status::off(e),
        }
    }
}

pub fn create_config(config_str: String) -> Result<FullConfig, String>
{
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

    let key = Key::clone_from_slice(config.key.as_bytes());

    let send_using_address = default_socket_send_address();
    let socket_address = BIND_ADDRESS
        .parse::<SocketAddr>()
        .expect("Incorrect default bind address");

    let protocol = match config.protocol.as_ref() {
        "basic" => Protocol::Basic,
        #[cfg(feature = "frames")]
        "frames" => Protocol::Frames,
        _ => return Err(format!("Protocol {} is not available", config.protocol)),
    };

    let group = Group {
        name: config.group,
        allowed_hosts: config.hosts,
        key: key,
        visible_ip: None,
        send_using_address,
        clipboard: String::from(DEFAULT_CLIPBOARD),
        protocol: protocol.clone(),
    };
    let groups = vec![group];
    let full_config = FullConfig::from_protocol_groups(
        protocol,
        socket_address,
        groups,
        MAX_RECEIVE_BUFFER,
        RECEIVE_ONCE_WAIT,
        false,
    );

    return Ok(full_config);
}

pub async fn create_runner(config_str: String) -> Result<(Runner, String), String>
{
    debug!("Start with config {}", config_str);
    let full_config = create_config(config_str)?;
    let runner = Runner::start(full_config).await;
    return Ok((runner, String::from("Started")));
}

pub struct Runner
{
    sender: JoinHandle<Result<u64, CliError>>,
    receiver: JoinHandle<Result<u64, CliError>>,
    running: Arc<AtomicBool>,
    stats: Receiver<(u64, u64)>,
    #[cfg(target_os = "android")]
    queue_sender: Arc<Sender<String>>,
    #[cfg(target_os = "android")]
    queue_receiver: Receiver<String>,
    received_count: u64,
    sent_count: u64,
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

        #[cfg(not(target_os = "android"))]
        let clipboard = String::from("");
        #[cfg(target_os = "android")]
        let mut clipboard = String::from("");
        #[cfg(target_os = "android")]
        while let Ok(c) = self.queue_receiver.try_recv() {
            clipboard = c;
        }

        return StatusCount {
            sent: self.sent_count,
            received: self.received_count,
            clipboard,
        };
    }

    #[cfg(target_os = "android")]
    pub fn queue(&mut self, contents: String) -> Result<(), String>
    {
        return self
            .queue_sender
            .try_send(contents)
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
                    Ok(c) => format!("receive count {}", c),
                    Err(e) => format!("receive error: {:?}", e),
                };

                let send_message = match send_result {
                    Ok(c) => format!("send count {}", c),
                    Err(e) => format!("send error: {:?}", e),
                };
                let result = format!("Finished running. {} {}", reiceive_message, send_message);
                info!("{}", result);
                return Ok(result);
            }
            Err(err) => {
                error!("{}", err);
                return Err(CliError::JoinError(err));
            }
        };
    }

    pub async fn start(full_config: FullConfig) -> Self
    {
        debug!("Starting runner");

        let running = Arc::new(AtomicBool::new(true));

        let (tx, rx) = channel(MAX_CHANNEL);
        let atx = Arc::new(tx);

        let (stat_sender, stat_receiver) = channel(MAX_CHANNEL);

        let stat_sender = Arc::new(stat_sender);

        #[cfg(target_os = "android")]
        let mut clipboard_receive: Clipboard = ChannelClipboardContext::new().unwrap();
        #[cfg(not(target_os = "android"))]
        let clipboard_receive: Clipboard = Clipboard::new().unwrap();

        #[cfg(target_os = "android")]
        let clipboard_send: Clipboard = ChannelClipboardContext::new().unwrap();
        #[cfg(not(target_os = "android"))]
        let clipboard_send: Clipboard = Clipboard::new().unwrap();

        #[cfg(target_os = "android")]
        let queue_sender = clipboard_send.get_sender();
        #[cfg(target_os = "android")]
        let queue_receiver = clipboard_receive.get_receiver().unwrap();

        let (protocol, bind_address) = full_config
            .get_first_bind_address()
            .expect("Protocol bind addresses required");

        let receive = wait_handle_receive(
            clipboard_receive,
            Arc::clone(&atx),
            bind_address.clone(),
            Arc::clone(&running),
            full_config.clone(),
            protocol.clone(),
            Arc::clone(&stat_sender),
            false,
        );

        let send = wait_on_clipboard(
            clipboard_send,
            rx,
            Arc::clone(&running),
            full_config.clone(),
            Arc::clone(&stat_sender),
            false,
        );

        return Runner {
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
        };
    }
}
