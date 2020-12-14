use log::{debug, error, info};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::defaults::MAX_UDP_BUFFER;
use crate::defaults::{CONNECTION_TIMEOUT, DATA_TIMEOUT, MAX_DATAGRAM_SIZE, QUIC_STREAM};
use crate::encryption::{decrypt, encrypt_to_bytes, hex_dump, random, validate};
use crate::errors::ConnectionError;
use crate::message::Group;

pub async fn send_data_quic(
    socket: UdpSocket,
    data: Vec<u8>,
    destination_addr: &SocketAddr,
    group: &Group,
) -> Result<usize, ConnectionError>
{
    let scid = random(quiche::MAX_CONN_ID_LEN);
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    let identity = socket.local_addr().map(|a| a.ip().to_string())?;

    let config_path = dirs::config_dir().ok_or_else(|| {
        ConnectionError::InvalidKey(
            "Quic unable to find config path with keys CONFIG_PATH is usually ~/.config".to_owned(),
        )
    })?;
    let cert_path = config_path.join(format!("clipboard-sync/cert.crt"));
    let crt_str = cert_path.to_string_lossy();

    config
        .load_verify_locations_from_file(&crt_str)
        .map_err(|e| {
            ConnectionError::InvalidKey(format!("verify crt not found {} {}", crt_str, e))
        })?;

    config
        .set_application_protos(b"\x05hq-29\x05hq-28\x05hq-27\x08http/0.9")
        .unwrap();

    config.verify_peer(false);
    config.set_max_idle_timeout(10000);
    config.set_max_udp_payload_size(MAX_DATAGRAM_SIZE as u64);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    let mut conn = quiche::connect(Some(&destination_addr.ip().to_string()), &scid, &mut config)?;

    let mut out = [0; MAX_DATAGRAM_SIZE];
    let mut buffer = [0; MAX_UDP_BUFFER];

    debug!(
        "Connecting to {:} from {:} with scid {}",
        destination_addr,
        socket.local_addr()?,
        hex_dump(&scid)
    );

    let cwrite = conn.send(&mut out)?;

    let enc_write = encrypt_to_bytes(&out[..cwrite], &identity, group)?;

    let mut connection_sent = match timeout(
        Duration::from_millis(CONNECTION_TIMEOUT),
        socket.send(&enc_write),
    )
    .await
    {
        Ok(v) => v?,
        Err(e) => {
            return Err(ConnectionError::FailedToConnect(format!(
                "Failed to send initial data {}",
                e
            )));
        }
    };

    debug!("Sent initial packet size {}", enc_write.len());

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
            connection_sent += csent;

            match socket.try_send(&buffer[..csent]) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break 'send_loop,
                Err(e) => {
                    return Err(ConnectionError::FailedToConnect(format!(
                        "Failed to send data {}",
                        e
                    )));
                }
            };
        }

        if conn.is_closed() {
            info!(
                "Client close connection sent {} read {} stats {:?}",
                connection_sent,
                connection_read,
                conn.stats()
            );
            return Ok(data_sent);
        }
    }
}

pub async fn receive_data_quic(
    socket: &UdpSocket,
    max_len: usize,
    groups: &[Group],
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

    config
        .load_cert_chain_from_pem_file(&crt_str)
        .map_err(|e| {
            ConnectionError::InvalidKey(format!("crt not found or not valid {} {}", crt_str, e))
        })?;
    config.load_priv_key_from_pem_file(&key_str).map_err(|e| {
        ConnectionError::InvalidKey(format!("key not found or not valid {} {}", key_str, e))
    })?;

    config
        .set_application_protos(b"\x05hq-29\x05hq-28\x05hq-27\x08http/0.9")
        .unwrap();

    config.set_max_idle_timeout(DATA_TIMEOUT);
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
    let mut connection_sent = 0;

    let (mut connection_read, addr) = socket.recv_from(&mut buffer).await?;
    // let mut pkt_buf = &mut buffer[..read];
    let pkt_buf_read = &buffer[..connection_read];

    // we dont need to retry with token if the first handshake is correct
    let (message, group) = validate(pkt_buf_read, groups)?;
    let mut pkt_buf = decrypt(&message, &addr.ip().to_string(), &group)?;

    let header = match quiche::Header::from_slice(&mut pkt_buf, quiche::MAX_CONN_ID_LEN) {
        Ok(v) => v,

        Err(e) => {
            error!("Parsing packet header failed: {:?}", e);
            return Err(ConnectionError::InvalidBuffer(format!(
                "Failed to read handshake"
            )));
        }
    };
    debug!(
        "Initial packet with size {} received {:?}",
        connection_read, header
    );

    let mut conn = quiche::accept(&header.scid, Some(&header.dcid), &mut config)?;
    let mut skip_initial = true;
    loop {
        if let Some(v) = conn.timeout() {
            if v.as_millis() == 0 {
                conn.on_timeout();
            }
        }

        'read_loop: loop {
            let sock_read;
            if skip_initial {
                let (read, sock_addr) = match socket.try_recv_from(&mut buffer) {
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
                sock_read = read;
                connection_read += read;

                if addr != sock_addr {
                    return Err(ConnectionError::InvalidBuffer(format!(
                        "Received from different address {} expected {}",
                        sock_addr, addr
                    )));
                }
            } else {
                sock_read = connection_read;
                skip_initial = false;
            }

            match conn.recv(&mut buffer[..sock_read]) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    break 'read_loop;
                }

                Err(e) => {
                    error!("Quic error occured while receiving {}", e);
                    return Err(ConnectionError::Http3(e));
                }
            };
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
            info!(
                "Server close connection sent {} read {} stats {:?}",
                connection_sent,
                connection_read,
                conn.stats()
            );
            return Ok((received, addr));
        }
    }
}

#[cfg(test)]
mod quichetest
{
    use super::*;
    use tokio::try_join;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_send_receive()
    {
        let local_server: SocketAddr = "127.0.0.1:9936".parse().unwrap();
        let local_client: SocketAddr = "127.0.0.1:9937".parse().unwrap();
        let server_sock = UdpSocket::bind(local_server).await.unwrap();
        let client_sock = UdpSocket::bind(local_client).await.unwrap();
        let group = Group::from_name("test1");
        let groups = vec![group.clone()];

        client_sock.connect(local_server).await.unwrap();

        let data_sent = b"test1".to_vec();
        let expect_data = data_sent.clone();

        let r = tokio::spawn(async move {
            // Process each socket concurrently.
            let (data_received, addr) =
                receive_data_quic(&server_sock, 100, &groups).await.unwrap();
            assert_eq!(expect_data, data_received);
            assert_eq!(local_client, addr);
        });

        let s = tokio::spawn(async move {
            let data_len_sent = send_data_quic(client_sock, data_sent, &local_server, &group)
                .await
                .unwrap();
            assert_eq!(data_len_sent, 5);
        });

        try_join!(r, s,).unwrap();
    }
}
