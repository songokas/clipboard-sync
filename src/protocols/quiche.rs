use chrono::{DateTime, Local};
use log::{debug, error, info, warn};
use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
// use ring::rand::SystemRandom;

use crate::defaults::MAX_UDP_BUFFER;
use crate::defaults::{MAX_DATAGRAM_SIZE, QUIC_STREAM};
use crate::encryption::{encrypt_to_bytes, decrypt, random, validate, hex_dump};
use crate::errors::ConnectionError;
use crate::message::Group;

pub async fn receive_data_quic(
    socket: &UdpSocket,
    max_len: usize,
    groups: &[Group]
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

    let config_path = dirs::config_dir().ok_or_else(|| {
        ConnectionError::InvalidKey(
            "Quic unable to find config path with keys CONFIG_PATH is usually ~/.config".to_owned(),
        )
    })?;
    let key_path = config_path.join(format!("clipboard-sync/cert.key"));
    let cert_path = config_path.join(format!("clipboard-sync/cert.crt"));
    let key_str = key_path.to_string_lossy();
    let crt_str = cert_path.to_string_lossy();

    config.load_cert_chain_from_pem_file(&crt_str)
        .map_err(|e| ConnectionError::InvalidKey(format!("crt not found or not valid {} {}", crt_str, e)))?;
    config.load_priv_key_from_pem_file(&key_str)
        .map_err(|e| ConnectionError::InvalidKey(format!("key not found or not valid {} {}", key_str, e)))?;

    config
        .set_application_protos(b"\x05hq-29\x05hq-28\x05hq-27\x08http/0.9")
        .unwrap();

    config.set_max_idle_timeout(5000);
    config.set_max_udp_payload_size(MAX_DATAGRAM_SIZE as u64);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_early_data();

    let mut received = Vec::new();
    let mut buffer = [0; MAX_UDP_BUFFER];
    // let mut out = [0; MAX_DATAGRAM_SIZE];
    let mut connection_received = 0;
    let mut connection_sent = 0;
    // let mut sending_addr = None;

    let (mut read, addr) = socket.recv_from(&mut buffer).await?;
    // let mut pkt_buf = &mut buffer[..read];
    let pkt_buf_read = &buffer[..read];

    // we dont need to retry with token if the first handshake is correct
    let (message, group) = validate(pkt_buf_read, groups)?;
    let mut pkt_buf = decrypt(&message, &addr.ip().to_string(), &group)?;

    // Parse the QUIC packet's header.
    let header = match quiche::Header::from_slice(&mut pkt_buf, quiche::MAX_CONN_ID_LEN) {
        Ok(v) => v,

        Err(e) => {
            error!("Parsing packet header failed: {:?}", e);
            return Err(ConnectionError::InvalidBuffer(format!(
                "Failed to read handshake"
            )));
        }
    };
    debug!("Initial packet with size {} received {:?}", read, header);

    let mut conn = quiche::accept(&header.scid, Some(&header.dcid), &mut config)?;
    let mut skip_initial = true;

    loop {
        if let Some(v) = conn.timeout() {
            if v.as_millis() == 0 {
                conn.on_timeout();
            }
        }
        'read_loop: loop {
            if skip_initial {
                let (sock_read, sock_addr) = match socket.try_recv_from(&mut buffer) {
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
                read = sock_read;
                if addr != sock_addr {
                    return Err(ConnectionError::InvalidBuffer(format!(
                        "Received from different address {} expected {}",
                        sock_addr, addr
                    )));
                }
            } else {
                skip_initial = false;
            }

            let read = match conn.recv(&mut buffer[..read]) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    break 'read_loop;
                }

                Err(e) => {
                    error!("Quic error occured while receiving {}", e);
                    return Err(ConnectionError::Http3(e));
                }
            };
            connection_received += read;
            // debug!("Quic socket read {} {}", read, connection_received);
        }

        if conn.is_in_early_data() || conn.is_established() {
            for stream_id in conn.readable() {
                debug!(
                    "Receive {} stream {} is readable",
                    conn.trace_id(),
                    stream_id
                );
                while let Ok((read, fin)) = conn.stream_recv(stream_id, &mut buffer) {
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
                        info!("Finished stream {}, closing...", stream_id);
                        conn.close(true, 0x00, b"kthxbye").unwrap();
                    }
                    if received.len() > max_len {
                        info!(
                            "Received bytes {} max expected {}, closing...",
                            received.len(),
                            max_len
                        );
                        conn.close(true, 0x00, b"kthxbye").unwrap_or(());
                        break;
                    }
                }
            }
        }

        'send_loop: loop {
            let write = match conn.send(&mut buffer) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    break 'send_loop;
                }

                Err(e) => {
                    error!("Quic error occured while sending {}", e);
                    return Err(ConnectionError::Http3(e));
                }
            };
            connection_sent += write;
            // debug!("Quic socket sent {} {}", write, connection_sent);

            match socket.try_send_to(&buffer[..write], addr) {
                Ok(s) => s,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
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

        if conn.is_closed() {
            debug!("ok connection closed, {:?}", conn.stats());
            return Ok((received, addr));
        }
    }
}

pub async fn send_data_quic(
    socket: UdpSocket,
    data: Vec<u8>,
    addr: &SocketAddr,
    group: &Group,
) -> Result<usize, ConnectionError>
{
    let scid = random(quiche::MAX_CONN_ID_LEN);
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

    let config_path = dirs::config_dir().ok_or_else(|| {
        ConnectionError::InvalidKey(
            "Quic unable to find config path with keys CONFIG_PATH is usually ~/.config".to_owned(),
        )
    })?;
    let cert_path = config_path.join(format!("clipboard-sync/cert.crt"));
    let crt_str = cert_path.to_string_lossy();

    config.load_verify_locations_from_file(&crt_str)
        .map_err(|e| ConnectionError::InvalidKey(format!("verify crt not found {} {}", crt_str, e)))?;

    config
        .set_application_protos(b"\x05hq-29\x05hq-28\x05hq-27\x08http/0.9")
        .unwrap();

    // config.verify_peer(false);
    config.set_max_idle_timeout(500);
    config.set_max_udp_payload_size(MAX_DATAGRAM_SIZE as u64);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    let mut conn = quiche::connect(Some(&addr.ip().to_string()), &scid, &mut config)?;

    let mut out = [0; MAX_DATAGRAM_SIZE];
    let mut buffer = [0; MAX_UDP_BUFFER];

    debug!(
        "Connecting to {:} from {:} with scid {}",
        addr,
        socket.local_addr()?,
        hex_dump(&scid)
    );

    let cwrite = conn.send(&mut out)?;

    let enc_write = encrypt_to_bytes(&out[..cwrite], &addr.ip().to_string(), group)?;
    while let Err(e) = socket.try_send(&enc_write) {
    // while let Err(e) = socket.try_send(&out[..cwrite]) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            continue;
        }

        return Err(ConnectionError::FailedToConnect(format!(
            "Failed to send initial data {}",
            e
        )));
    }

    // debug!("Sent initial packet size {}", cwrite);
    debug!("Sent initial packet size {}", enc_write.len());

    let mut connection_sent = 0;
    let mut connection_read = 0;
    let mut data_sent = 0;

    loop {
        if let Some(v) = conn.timeout() {
            if v.as_millis() == 0 {
                conn.on_timeout();
            }
        }

        'read_loop: loop {
            let slen = match socket.try_recv(&mut buffer) {
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

            connection_read += slen;

            // Process potentially coalesced packets.
            match conn.recv(&mut buffer[..slen]) {
                Ok(v) => v,
                Err(quiche::Error::Done) => {
                    break 'read_loop;
                }
                Err(e) => {
                    error!("Quic error occured while receiving {}", e);
                    return Err(ConnectionError::Http3(e));
                }
            };
            // debug!("Quic socket received {} {}", cread, connection_read);
        }

        if conn.is_established() {
            while let Ok(sent) = conn.stream_send(QUIC_STREAM as u64, &data[data_sent..], true) {
                if sent == 0 {
                    break;
                }
                data_sent += sent;
                debug!("Quic stream sent bytes {} {}", sent, data_sent);
            }
        }

        'send_loop: loop {
            let csent = match conn.send(&mut buffer) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    break 'send_loop;
                }

                Err(e) => {
                    error!("Connection failed to send: {:?}", e);
                    conn.close(false, 0x1, b"fail").ok();
                    break 'send_loop;
                }
            };

            if let Err(e) = socket.try_send(&buffer[..csent]) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    break 'send_loop;
                }

                return Err(ConnectionError::FailedToConnect(format!(
                    "Failed to send data {}",
                    e
                )));
            }
            connection_sent += csent;
            // debug!("Quic socket sent {} {}", csent, connection_sent);
        }

        if conn.is_closed() {
            info!("ok connection closed, {:?}", conn.stats());
            return Ok(data_sent);
        }
    }
}

