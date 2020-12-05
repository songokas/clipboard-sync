use log::{debug, error, info, warn};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use tokio::net::UdpSocket;
// #[cfg(feature = "frames")]
// #[cfg(feature = "quic")]
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

#[cfg(feature = "quic")]
use crate::defaults::MAX_DATAGRAM_SIZE;
use crate::defaults::MAX_UDP_BUFFER;
use crate::errors::ConnectionError;
use crate::message::Group;
use std::convert::TryInto;
use std::io;

use crate::encryption::{decrypt, encrypt_to_bytes, validate};

pub fn obtain_local_addr(sock: &UdpSocket) -> Result<IpAddr, ConnectionError>
{
    return sock
        .local_addr()
        .map(|s| s.ip().clone())
        .map_err(|err| ConnectionError::IoError(err));
}

pub async fn obtain_socket(
    local_address: &SocketAddr,
    remote_addr: &SocketAddr,
) -> Result<UdpSocket, ConnectionError>
{
    debug!("Send to {} using {}", remote_addr, local_address);
    let sock = UdpSocket::bind(local_address).await?;
    sock.connect(remote_addr).await?;
    return Ok(sock);
}

pub fn join_group(sock: &UdpSocket, interface_addr: &IpAddr, remote_ip: &IpAddr)
{
    let interface_ipv4 = match interface_addr {
        IpAddr::V4(ipv4) => ipv4,
        _ => {
            warn!("Ipv6 multicast not supported");
            return;
        }
    };

    let op = match remote_ip {
        IpAddr::V4(multicast_ipv4) => {
            sock.set_multicast_loop_v4(false).unwrap_or(());
            sock.join_multicast_v4(multicast_ipv4.clone(), interface_ipv4.clone())
        }
        _ => {
            warn!("Ipv6 multicast not supported");
            return;
        }
    };
    if let Err(_) = op {
        warn!("Unable to join multicast network");
    } else {
        debug!("Joined multicast {}", remote_ip);
    }
}

pub fn join_groups(sock: &UdpSocket, groups: &[Group], ipv4: &Ipv4Addr)
{
    let mut cache = HashMap::new();
    for group in groups {
        for addr in &group.allowed_hosts {
            if cache.contains_key(&addr.ip()) {
                continue;
            }
            if addr.ip().is_multicast() {
                let op = match addr.ip() {
                    IpAddr::V4(ip) => {
                        sock.set_multicast_loop_v4(false).unwrap_or(());
                        sock.join_multicast_v4(ip, ipv4.clone())
                    }
                    _ => {
                        warn!("Multicast ipv6 not supported");
                        continue;
                    }
                };
                if let Err(_) = op {
                    warn!("Unable to join multicast {}", addr.ip());
                    continue;
                } else {
                    cache.insert(addr.ip(), true);
                    info!("Joined multicast {}", addr.ip());
                }
            }
        }
    }
}

pub async fn send_data(
    socket: UdpSocket,
    data: Vec<u8>,
    addr: &SocketAddr,
    group: &Group,
    protocol: &str,
) -> Result<usize, ConnectionError>
{
    return match protocol {
        #[cfg(feature = "frames")]
        "frames" => send_data_frames(socket, data, addr, group).await,
        #[cfg(feature = "quic")]
        "quic" => send_data_quic(socket, data).await,
        #[cfg(feature = "basic")]
        "basic" => send_data_basic(socket, data).await,
        _ => Err(ConnectionError::InvalidProtocol(protocol.to_owned())),
    };
}

pub async fn receive_data(
    socket: &UdpSocket,
    max_len: usize,
    groups: &[Group],
    protocol: &str,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    return match protocol {
        #[cfg(feature = "frames")]
        "frames" => receive_data_frames(socket, max_len, groups).await,
        #[cfg(feature = "quic")]
        "quic" => receive_data_quic(socket, max_len).await,
        #[cfg(feature = "basic")]
        "basic" => receive_data_basic(socket, max_len).await,
        _ => Err(ConnectionError::InvalidProtocol(protocol.to_owned())),
    };
}

#[cfg(feature = "basic")]
pub async fn receive_data_basic(
    socket: &UdpSocket,
    max_len: usize,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let mut data = vec![0; max_len];
    let (_, addr) = socket.recv_from(&mut data).await?;
    return Ok((data, addr));
}

#[cfg(feature = "basic")]
pub async fn send_data_basic(socket: UdpSocket, data: Vec<u8>) -> Result<usize, ConnectionError>
{
    return Ok(socket.send(&data).await?);
}

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

#[cfg(feature = "quic")]
pub async fn receive_data_quic(
    socket: &UdpSocket,
    max_len: usize,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let scid = [0xba; 16];
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.set_max_idle_timeout(5000);
    config.verify_peer(false);
    config.set_max_udp_payload_size(MAX_DATAGRAM_SIZE as u64);
    config.load_cert_chain_from_pem_file("/tmp/cert.crt")?;
    config.load_priv_key_from_pem_file("/tmp/cert.key")?;

    let mut conn = quiche::accept(&scid, None, &mut config)?;
    let mut received = Vec::new();
    let mut buffer = [0; MAX_UDP_BUFFER];
    let mut out = [0; MAX_DATAGRAM_SIZE];
    let mut connection_received = 0;
    let mut connection_sent = 0;
    let mut sending_addr = None;
    loop {
        'read_loop: loop {
            let (read, addr) = match socket.try_recv_from(&mut buffer) {
                Ok(n) => n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break 'read_loop;
                }
                Err(e) => {
                    error!("Quic error occured while reading socket {}", e);
                    return Err(ConnectionError::InvalidBuffer(format!(
                        "Failed to read socket"
                    )));
                }
            };
            // let (read, addr) = socket.recv_from(&mut data).await?;
            if sending_addr.is_none() {
                sending_addr = Some(addr);
            }

            debug!("Quic connection received {}", read);

            let read = match conn.recv(&mut buffer[..read]) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("Quic connection finished receiving");
                    break 'read_loop;
                    // return Ok((received, addr));
                }

                Err(e) => {
                    error!("Quick error occured while receiving {}", e);
                    return Err(ConnectionError::Http3(e));
                }
            };
            connection_received += read;

            // let pkt_buf = &mut data[..read];

            // Parse the QUIC packet's header.
            // let header = match quiche::Header::from_slice(
            //     pkt_buf,
            //     quiche::MAX_CONN_ID_LEN,
            // ) {
            //     Ok(v) => v,

            //     Err(e) => {
            //         error!("Parsing packet header failed: {:?}", e);
            //         return Err(ConnectionError::Http3(e));
            //     },
            // };
            // let mut copy = data[..read].to_vec();
            // received.append(&mut copy);

            // debug!("Total conn read {} received {} closed {} {:?}", read, received.len(), conn.is_closed(), conn.stats());
            // if received.len() > max_len {
            //     return Err(ConnectionError::InvalidBuffer(format!(
            //         "Received more data {} than expected {}",
            //         received.len(),
            //         max_len,
            //     )));
            // }
        }

        'send_loop: loop {

            let write = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    // debug!("Quic connection finished sending");
                    break 'send_loop;
                }

                Err(e) => {
                    error!("Quic error occured while sending {}", e);
                    return Err(ConnectionError::Http3(e));
                }
            };

            connection_sent += write;
            match socket.try_send_to(&out[..write], sending_addr.unwrap()) {
                Ok(s) => s,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    debug!("Quic connection socket finished sending");
                    break 'send_loop;
                }
                Err(e) => {
                    error!("Quic error occured while writing socket {}", e);
                    return Err(ConnectionError::InvalidBuffer(format!(
                        "Quic failed to send socket"
                    )));
                }
            };

        }

        // debug!(
        //     "Quick connection sent {} received {}",
        //     connection_sent, connection_received
        // );

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            return Err(ConnectionError::InvalidBuffer(format!(
                "quic connection closed"
            )));
        }

        if conn.is_in_early_data() || conn.is_established() {
            debug!("Connection established {:?}", conn.stats());
            while let Ok((read, fin)) = conn.stream_recv(0, &mut buffer) {
                let mut copy = buffer[..read].to_vec();
                received.append(&mut copy);
                debug!(
                    "Total conn read {} received {} fin {} closed {} {:?}",
                    read,
                    received.len(),
                    fin,
                    conn.is_closed(),
                    conn.stats()
                );
                if fin {
                    info!("response received in {:?}, closing...", fin);
                    conn.close(true, 0x00, b"kthxbye").unwrap();
                }
            }
        }
    }
    return Ok((received, sending_addr.unwrap()));
}

#[cfg(feature = "quic")]
pub async fn send_data_quic(socket: UdpSocket, mut data: Vec<u8>)
    -> Result<usize, ConnectionError>
{
    let scid = [0xba; 16];
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.set_max_idle_timeout(5000);
    // config.verify_peer(false);
    config.set_max_udp_payload_size(MAX_DATAGRAM_SIZE as u64);
    // config.load_cert_chain_from_pem_file("/tmp/cert.crt")?;
    // config.load_priv_key_from_pem_file("/tmp/key.pem")?;
    // let mut conn = quiche::accept(&scid, None, &mut config)?;
    let mut conn = quiche::connect(None, &scid, &mut config)?;

    let mut out = [0; MAX_DATAGRAM_SIZE];
    let mut buffer = [0; MAX_UDP_BUFFER];

    // conn.on_timeout();

    // sender
    let mut connect_sent = 0;
    // loop {
    //     let write = match conn.send(&mut out) {
    //         Ok(v) => v,

    //         Err(quiche::Error::Done) => {
    //             debug!("Quic connection finished");
    //             break;
    //         }

    //         Err(e) => {
    //             error!("Quic error occured while sending {}", e);
    //             return Err(ConnectionError::Http3(e));
    //         }
    //     };

    //     connect_sent += write;
    //     socket.send(&out[..write]).await?;
    // }

    // debug!("Quick connection sent {}", connect_sent);

    loop {
        'send_loop: loop {
            let write = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    break 'send_loop;
                    // debug!("done writing");
                    // return Ok(data_sent);
                }

                Err(e) => {
                    error!("send failed: {:?}", e);
                    conn.close(false, 0x1, b"fail").ok();
                    break 'send_loop;
                }
            };

            if let Err(e) = socket.try_send(&out[..write]) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!("send() would block");
                    break 'send_loop;
                }

                panic!("send() failed: {:?}", e);
            }

            debug!("written {}", write);
        }

        'read_loop: loop {
            let len = match socket.try_recv(&mut buffer) {
                Ok(n) => n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break 'read_loop;
                }
                Err(e) => {
                    error!("Quic error occured while reading socket {}", e);
                    return Err(ConnectionError::InvalidBuffer(format!(
                        "Failed to read socket"
                    )));
                }
            };

            // debug!("Quic received {} bytes", len);

            // Process potentially coalesced packets.
            let read = match conn.recv(&mut buffer[..len]) {
                Ok(v) => v,
                Err(quiche::Error::Done) => {
                    debug!("Quic connection finished receiving");
                    break 'read_loop;
                }
                Err(e) => {
                    error!("Quick error occured while receiving {}", e);
                    return Err(ConnectionError::Http3(e));
                }
            };
            debug!("Quick processed {} bytes", read);
        }


        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            return Err(ConnectionError::InvalidBuffer(format!(
                "quic connection closed"
            )));
        }

        let mut data_sent = 0;
        if conn.is_established() {
            debug!("Connection established {:?}", conn.stats());

            while let Ok(sent) = conn.stream_send(0, &mut data, true) {
                debug!("Quic sent bytes {} on stream 0", sent);
                data_sent += sent;
            }
        }

        for s in conn.readable() {
            while let Ok((read, fin)) = conn.stream_recv(s, &mut buffer) {
                debug!("received {} bytes", read);

                let stream_buf = &buffer[..read];

                debug!("stream {} has {} bytes (fin? {})", s, stream_buf.len(), fin);

                debug!("{}", unsafe { std::str::from_utf8_unchecked(&stream_buf) });

                // The server reported that it has no more data to send, which
                // we got the full response. Close the connection.
                if s == 0 && fin {
                    info!("response received in {:?}, closing...", fin);
                    conn.close(true, 0x00, b"kthxbye").unwrap();
                }
            }
        }
    }

    // return Ok(data_sent);
}
