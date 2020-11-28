#![feature(ip)]

use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use rand::prelude::*;
use std::{thread, time};

use base64::encode;
use bincode;
use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; // Or `XChaCha20Poly1305`
use chrono::Utc;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io;
use std::net::IpAddr;
use std::iter::Iterator;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};
use tokio::sync::mpsc::{channel, Sender, Receiver};

use clap::{load_yaml, App};
use env_logger::Env;
use futures::join;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;

pub mod errors;
pub mod message;
pub mod process;
pub mod encryption;

use crate::errors::CliError;
use crate::message::{Group};
use crate::process::{wait_on_clipboard, wait_on_receive};

const MAX_CHANNEL: usize = 100;


pub fn load_groups(file_path: &str) -> Result<Vec<Group>, CliError>
{
    return Err(CliError::MissingFile("config not implemented".to_owned()));
}

#[tokio::main]
async fn main() -> Result<(), CliError>
{
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let verbosity: u8 = matches.occurrences_of("verbose") as u8;
    let config_path = matches.value_of("config");

    let local_address = matches.value_of("bind-address").unwrap_or("0.0.0.0:8900");
    let send_address = matches.value_of("send-address")
        .unwrap_or("0.0.0.0:8901");
    let public_ip = matches.value_of("public-ip")
        .and_then(|ip| ip.parse::<IpAddr>().ok());

    let group = matches.value_of("group").unwrap_or("default");

    let allowed_host = matches.value_of("allowed-host").unwrap_or("224.0.0.89");
    let key_data = matches.value_of("key").unwrap_or("");

    if config_path.is_none() {
        if key_data.len() != 32 {
            return Err(CliError::ArgumentError(
                format!("Please provide a valid key with length 32. Current: {}", key_data.len()),
            ));
        }
    }

    let socket_address = local_address
        .parse::<SocketAddr>()
        .map_err(|err| CliError::ArgumentError(err.to_string()))?;

    let create_groups = || -> Result<Vec<Group>, CliError> {
        let allowed_host_addr = allowed_host.parse::<SocketAddr>()?;
        let send_using_address = send_address.parse::<SocketAddr>()?;
        let key = Key::from_slice(key_data.as_bytes());
        Ok(vec![Group {
            name: group.to_owned(),
            allowed_hosts: vec![allowed_host_addr],
            key: key.clone(),
            public_ip,
            send_using_address
        }])
    };

    let groups = config_path
        .map(|config_path| load_groups(&config_path))
        .unwrap_or_else(create_groups)?;

    let running = Arc::new(AtomicBool::new(true));

    env_logger::from_env(Env::default().default_filter_or(match verbosity {
        1 => "debug",
        2 => "trace",
        _ => "info",
    }))
    .init();

    let (tx, rx) = channel(MAX_CHANNEL);

    join!(
        wait_on_receive(tx, socket_address, Arc::clone(&running), &groups),
        wait_on_clipboard(rx, Arc::clone(&running), &groups)
    );

    Ok(())
}
