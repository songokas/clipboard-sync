use log::{debug, error, info, warn};
use std::collections::{BTreeMap, HashMap};
use std::net::{SocketAddr};
use tokio::net::ToSocketAddrs;
use std::net::{IpAddr, Ipv4Addr};
use tokio::net::UdpSocket;
// #[cfg(feature = "frames")]
// #[cfg(feature = "quic")]
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use rand::prelude::*;
use quinn::{Endpoint, Incoming};

#[cfg(feature = "quic")]
use crate::defaults::MAX_DATAGRAM_SIZE;
use crate::defaults::MAX_UDP_BUFFER;
use crate::errors::ConnectionError;
use crate::filesystem::read_file;
use crate::message::Group;
use std::convert::TryInto;
use std::io;
use crate::encryption::{decrypt, encrypt_to_bytes, validate};

#[cfg(feature = "frames")]
#[derive(Serialize, Deserialize, Debug)]
pub struct Frame
{
    index: u32,
    total: u16,
    data: Vec<u8>,
}

#[cfg(feature = "frames")]
pub async fn receive_data_frames(
    socket: &UdpSocket,
    max_len: usize,
    groups: &[Group],
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let mut received_frames: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut data = [0; MAX_UDP_BUFFER];
    let mut received = 0;
    let mut last_addr: Option<SocketAddr> = None;

    loop {
        // this could be multiple addresses
        let (read, addr) = socket.recv_from(&mut data).await?;

        received += read;

        if received > max_len {
            return Err(ConnectionError::InvalidBuffer(format!(
                "Received more data {} than expected {}",
                received, max_len
            )));
        }

        if last_addr.is_none() {
            last_addr = Some(addr);
        }

        if last_addr.unwrap() != addr {
            return Err(ConnectionError::InvalidBuffer(
                "Received data from different address".to_owned(),
            ));
        }

        let (message, group) = validate(&data, groups)?;
        let bytes = decrypt(&message, &addr.ip().to_string(), &group)?;

        let frame: Frame = bincode::deserialize(&bytes)
            .map_err(|err| ConnectionError::InvalidBuffer((*err).to_string()))?;

        debug!(
            "Read {} bytes from {}, index {} total {}",
            read, addr, frame.index, frame.total
        );

        received_frames.insert(frame.index, frame.data);

        let bytes = encrypt_to_bytes(&frame.index.to_be_bytes(), &addr.ip().to_string(), &group)?;
        socket.send_to(&bytes, addr).await?;

        if frame.total as usize == received_frames.len() {
            let mut full = Vec::new();
            for (_, mut frame) in received_frames {
                full.append(&mut frame);
            }
            return Ok((full, addr));
        }
    }
}

#[cfg(feature = "frames")]
async fn send_index(
    socket_writer: &UdpSocket,
    index: u32,
    indexes: usize,
    data: &[u8],
    addr: &SocketAddr,
    group: &Group,
) -> Result<usize, ConnectionError>
{
    let max_that_fit: usize = MAX_UDP_BUFFER - 300;
    let from = index as usize * max_that_fit;
    let mut to = (index as usize + 1) * max_that_fit;
    if to > data.len() {
        to = data.len();
    }
    let frame = Frame {
        index: index as u32,
        total: indexes as u16,
        data: data[from..to].to_vec(),
    };
    let bytes = bincode::serialize(&frame)
        .map_err(|err| ConnectionError::InvalidBuffer((*err).to_string()))?;
    let bytes = encrypt_to_bytes(&bytes, &addr.ip().to_string(), &group)?;

    debug!("Sent frame {} with {} bytes", index, bytes.len());

    return Ok(socket_writer.send(&bytes).await?);
}

#[cfg(feature = "frames")]
pub async fn send_data_frames(
    socket: UdpSocket,
    data: Vec<u8>,
    addr: &SocketAddr,
    group: &Group,
) -> Result<usize, ConnectionError>
{
    let indexes: usize = (data.len() / MAX_UDP_BUFFER) + 1;
    let socket_writer = Arc::new(socket);
    let socket_reader = Arc::clone(&socket_writer);
    let groups = vec![group.clone()];
    let expected_addr = addr.clone();

    let mut sent = 0;
    let (channel_sender, mut channel_receiver) = mpsc::channel(indexes * 4);

    tokio::spawn(async move {
        let mut received: HashMap<u32, bool> = HashMap::new();
        while received.len() != indexes && !channel_sender.is_closed() {
            let mut bytes = [0; 100];
            let received_bytes = match socket_reader.recv(&mut bytes).await {
                Ok(_) => validate(&bytes, &groups)
                    .map_err(ConnectionError::ReceiveError)
                    .and_then(|(message, cgroup)| {
                        decrypt(&message, &expected_addr.ip().to_string(), &cgroup)
                            .map_err(ConnectionError::Encryption)
                    }),
                _ => {
                    continue;
                }
            };

            let index_bytes = match received_bytes {
                Ok(b) if b.len() == 4 => b.try_into(),
                Ok(b) => {
                    warn!(
                        "Received confirmation with incorrect data len {} {:?}",
                        b.len(),
                        b
                    );
                    continue;
                }
                Err(e) => {
                    warn!("Failed to receive confirmation: {:?}", e);
                    continue;
                }
            };

            let index = match index_bytes {
                Ok(b) => u32::from_be_bytes(b),
                _ => {
                    warn!("Failed to retrieve bytes");
                    continue;
                }
            };

            debug!("Received frame confirmation {}", index);

            if (index as usize) < indexes {
                received.insert(index, true);
                if let Err(e) = channel_sender.try_send(index) {
                    error!("Failed to send index {} to channel {}", index, e);
                }
            }
        }
    });

    let mut sent_without_confirmation: HashMap<u32, bool> = HashMap::new();
    let mut i: u32 = 0;
    // first send all
    while i < indexes as u32 {
        sent += send_index(&socket_writer, i, indexes, &data, addr, group).await?;
        sent_without_confirmation.insert(i, true);
        i += 1;
        sleep(Duration::from_millis(20)).await;
    }

    // try for 5s
    let mut retries: u8 = 50;
    while sent_without_confirmation.len() > 0 && retries > 0 {
        let mut i = 0;
        sleep(Duration::from_millis(100)).await;
        while i < 5000 && sent_without_confirmation.len() > 0 {
            if let Ok(index) = channel_receiver.try_recv() {
                if let None = sent_without_confirmation.remove(&index) {
                    error!("Error non exist frame index");
                }
            }
            i += 1;
        }

        for (index, _) in sent_without_confirmation.iter() {
            sent += send_index(&socket_writer, index.clone(), indexes, &data, addr, group).await?;
        }
        retries -= 1;
    }
    channel_receiver.close();
    if retries == 0 {
        return Err(ConnectionError::FailedToConnect(format!(
            "Unable to send data frames"
        )));
    }
    return Ok(sent);
}