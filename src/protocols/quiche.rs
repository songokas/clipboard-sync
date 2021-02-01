use log::{debug, error, info};
use quiche::{Config, Connection, Header};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::defaults::MAX_UDP_BUFFER;
use crate::defaults::{CONNECTION_TIMEOUT, DATA_TIMEOUT, MAX_DATAGRAM_SIZE, QUIC_STREAM};
use crate::encryption::{decrypt, encrypt_to_bytes, hex_dump, random, validate};
use crate::errors::ConnectionError;
use crate::message::{Group, MessageType};
use crate::socket::receive_from_timeout;

pub async fn send_data_quic(
    socket: UdpSocket,
    data: Vec<u8>,
    destination_addr: &SocketAddr,
    group: &Group,
    verify_path: Option<String>,
) -> Result<usize, ConnectionError>
{
    let scid = random(quiche::MAX_CONN_ID_LEN);
    let mut config = load_client_config(verify_path)?;

    let mut conn = quiche::connect(Some(&destination_addr.ip().to_string()), &scid, &mut config)?;

    debug!(
        "Connecting to {:} from {:} with scid {}",
        destination_addr,
        socket.local_addr()?,
        hex_dump(&scid)
    );

    let mut connection_sent = send_handshake(&mut conn, &socket, group).await?;

    debug!("Sent initial packet size {}", connection_sent);

    let mut connection_read = 0;
    let mut data_sent = 0;

    loop {
        if let Some(v) = conn.timeout() {
            if v.as_millis() == 0 {
                conn.on_timeout();
            }
        }

        connection_read += receive(&mut conn, &socket, None)?;

        if conn.is_established() {
            while let Ok(sent) = conn.stream_send(QUIC_STREAM as u64, &data[data_sent..], true) {
                if sent == 0 {
                    break;
                }
                data_sent += sent;
                debug!("Quic stream sent bytes {} {}", sent, data_sent);
            }
        }

        connection_sent += send(&mut conn, &socket, None)?;

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
    private_key: &str,
    public_key: &str,
    timeout_callback: impl Fn(Duration) -> bool,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let mut config = load_server_config(private_key, public_key)?;
    let mut connection_sent = 0;
    let mut received = Vec::new();
    let timeout = DATA_TIMEOUT as u128;

    let (header, addr, mut buffer, mut connection_read) =
        receive_handshake(&socket, groups, timeout_callback).await?;

    debug!(
        "Initial packet with size {} received {:?}",
        connection_read, header
    );

    let mut conn = quiche::accept(&header.scid, Some(&header.dcid), &mut config)?;

    match conn.recv(&mut buffer) {
        Ok(v) => v,
        Err(quiche::Error::Done) => 0,
        Err(e) => {
            error!("Quic error occured while receiving {}", e);
            return Err(ConnectionError::Http3(e));
        }
    };

    let now = Instant::now();

    loop {
        if let Some(v) = conn.timeout() {
            if v.as_millis() == 0 {
                conn.on_timeout();
            }
        }

        connection_read += receive(&mut conn, &socket, Some(addr))?;

        if conn.is_in_early_data() || conn.is_established() {
            for stream_id in conn.readable() {
                debug!(
                    "Receive {} stream {} is readable",
                    conn.trace_id(),
                    stream_id
                );
                receive_stream(&mut conn, stream_id, &mut received, max_len)?;
            }
        }

        connection_sent += send(&mut conn, &socket, Some(addr))?;

        if conn.is_closed() {
            info!(
                "Server close connection sent {} read {} stats {:?}",
                connection_sent,
                connection_read,
                conn.stats()
            );
            return Ok((received, addr));
        }

        if now.elapsed().as_millis() > timeout {
            return Err(ConnectionError::FailedToConnect(format!(
                "Connection timeout {}. Received {} Sent {}",
                now.elapsed().as_millis(),
                connection_read,
                connection_sent
            )));
        }
    }
}

fn receive_stream(
    conn: &mut Connection,
    stream_id: u64,
    received: &mut Vec<u8>,
    max_len: usize,
) -> Result<(), ConnectionError>
{
    let mut buffer = [0; MAX_UDP_BUFFER];
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
    return Ok(());
}

async fn send_handshake(
    conn: &mut Connection,
    socket: &UdpSocket,
    group: &Group,
) -> Result<usize, ConnectionError>
{
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let identity = socket.local_addr().map(|a| a.ip().to_string())?;

    let cwrite = conn.send(&mut out)?;

    let enc_write = encrypt_to_bytes(&out[..cwrite], &identity, group, &MessageType::Handshake)?;

    let connection_sent = match timeout(
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
    return Ok(connection_sent);
}

async fn receive_handshake(
    socket: &UdpSocket,
    groups: &[Group],
    timeout: impl Fn(Duration) -> bool,
) -> Result<(Header, SocketAddr, Vec<u8>, usize), ConnectionError>
{
    let mut buffer = [0; MAX_UDP_BUFFER];
    let (connection_read, addr) = receive_from_timeout(socket, &mut buffer, timeout).await?;
    let pkt_buf_read = &buffer[..connection_read];

    // we dont need to retry with token if the first handshake is correct
    let (message, group) = validate(pkt_buf_read, groups)?;
    let mut pkt_buf = decrypt(&message, &addr.ip().to_string(), &group)?;

    let header = match Header::from_slice(&mut pkt_buf, quiche::MAX_CONN_ID_LEN) {
        Ok(v) => v,

        Err(e) => {
            error!("Parsing packet header failed: {:?}", e);
            return Err(ConnectionError::InvalidBuffer(format!(
                "Failed to read handshake"
            )));
        }
    };

    return Ok((header, addr, pkt_buf, connection_read));
}

fn receive(
    conn: &mut Connection,
    socket: &UdpSocket,
    expected_addr: Option<SocketAddr>,
) -> Result<usize, ConnectionError>
{
    let mut buffer = [0; MAX_UDP_BUFFER];
    let mut connection_read = 0;

    'read_loop: loop {
        let (slen, sock_addr) = match socket.try_recv_from(&mut buffer) {
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

        if let Some(addr) = expected_addr {
            if addr != sock_addr {
                return Err(ConnectionError::InvalidBuffer(format!(
                    "Received from different address {} expected {}",
                    sock_addr, addr
                )));
            }
        }

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
    return Ok(connection_read);
}

fn send(
    conn: &mut Connection,
    socket: &UdpSocket,
    to_addr: Option<SocketAddr>,
) -> Result<usize, ConnectionError>
{
    let mut buffer = [0; MAX_UDP_BUFFER];
    let mut connection_sent = 0;
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

        let op = if let Some(addr) = to_addr {
            socket.try_send_to(&buffer[..csent], addr)
        } else {
            socket.try_send(&buffer[..csent])
        };

        match op {
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
    return Ok(connection_sent);
}

fn load_config() -> Result<Config, ConnectionError>
{
    let mut config = Config::new(quiche::PROTOCOL_VERSION)?;
    config
        .set_application_protos(b"\x05hq-29\x05hq-28\x05hq-27\x08http/0.9")
        .unwrap();

    config.set_max_idle_timeout(CONNECTION_TIMEOUT);
    config.set_max_udp_payload_size(MAX_DATAGRAM_SIZE as u64);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_early_data();
    return Ok(config);
}

fn load_client_config(verify_path: Option<String>) -> Result<Config, ConnectionError>
{
    let mut config = load_config()?;

    if let Some(crt_str) = verify_path {
        config
            .load_verify_locations_from_file(&crt_str)
            .map_err(|e| {
                ConnectionError::InvalidKey(format!("verify crt not found {} {}", crt_str, e))
            })?;
    } else {
        config.verify_peer(false);
    }
    return Ok(config);
}

fn load_server_config(key_path: &str, cert_path: &str) -> Result<Config, ConnectionError>
{
    let mut config = load_config()?;
    config
        .load_cert_chain_from_pem_file(cert_path)
        .map_err(|e| {
            ConnectionError::InvalidKey(format!(
                "certificate not found or not valid {} {}",
                cert_path, e
            ))
        })?;
    config.load_priv_key_from_pem_file(key_path).map_err(|e| {
        ConnectionError::InvalidKey(format!("key not found or not valid {} {}", key_path, e))
    })?;

    return Ok(config);
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
            let (data_received, addr) = receive_data_quic(
                &server_sock,
                100,
                &groups,
                "tests/cert.key",
                "tests/cert.crt",
                |d: Duration| d > Duration::from_millis(2000),
            )
            .await
            .unwrap();
            assert_eq!(expect_data, data_received);
            assert_eq!(local_client, addr);
        });

        let s = tokio::spawn(async move {
            let data_len_sent = send_data_quic(client_sock, data_sent, &local_server, &group, None)
                .await
                .unwrap();
            assert_eq!(data_len_sent, 5);
        });

        try_join!(r, s,).unwrap();
    }
}
