use log::{debug, error, info, warn};
use std::collections::{BTreeMap, HashMap};
use std::net::{SocketAddr};
use tokio::net::ToSocketAddrs;
use std::net::{IpAddr, Ipv4Addr};
use tokio::net::UdpSocket;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use rand::prelude::*;
use quinn::{Endpoint, Incoming};

use crate::defaults::MAX_DATAGRAM_SIZE;
use crate::defaults::MAX_UDP_BUFFER;
use crate::errors::ConnectionError;
use crate::filesystem::read_file;
use crate::message::Group;
use std::convert::TryInto;
use std::io;
use crate::encryption::{decrypt, encrypt_to_bytes, validate};

pub async fn receive_data_basic(
    socket: &UdpSocket,
    max_len: usize,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let mut data = vec![0; max_len];
    let (_, addr) = socket.recv_from(&mut data).await?;
    return Ok((data, addr));
}

pub async fn send_data_basic(socket: UdpSocket, data: Vec<u8>) -> Result<usize, ConnectionError>
{
    return Ok(socket.send(&data).await?);
}