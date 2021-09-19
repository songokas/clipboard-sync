use log::{debug, error, info};
use quiche::{Config, Connection, ConnectionId, Header};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::defaults::{CONNECTION_TIMEOUT, MAX_DATAGRAM_SIZE, MAX_UDP_BUFFER, QUIC_STREAM};
use crate::encryption::{hex_dump, random};
use crate::errors::ConnectionError;
use crate::fragmenter::{FrameDecryptor, FrameEncryptor};
use crate::identity::Identity;
use crate::message::MessageType;
use crate::socket::{receive_from_timeout, Destination};

pub async fn send_data(
    socket: Arc<UdpSocket>,
    encryptor: impl FrameEncryptor,
    data: Vec<u8>,
    destination: Destination,
    verify_path: Option<String>,
    timeout_callback: impl Fn(Duration) -> bool,
) -> Result<usize, ConnectionError>
{
    let scid = random(quiche::MAX_CONN_ID_LEN);
    let mut config = load_client_config(verify_path)?;
    let connection_id = ConnectionId::from_vec(scid.clone());

    let mut conn = quiche::connect(Some(destination.host()), &connection_id, &mut config)?;

    debug!(
        "Connecting to {:} from {:} with scid {}",
        destination,
        socket.local_addr()?,
        hex_dump(&scid)
    );

    let mut connection_sent = send_handshake(
        &mut conn,
        &socket,
        *destination.addr(),
        encryptor,
        timeout_callback,
    )
    .await?;

    debug!("Sent initial packet size {}", connection_sent);

    let mut connection_read = 0;
    let mut data_sent = 0;
    let now = Instant::now();

    loop {
        if let Some(v) = conn.timeout() {
            if v.as_millis() == 0 {
                conn.on_timeout();
            }
        }

        connection_read += receive(&mut conn, &socket, Some(*destination.addr()))?;

        if conn.is_established() {
            while let Ok(sent) = conn.stream_send(QUIC_STREAM as u64, &data[data_sent..], true) {
                if sent == 0 {
                    break;
                }
                data_sent += sent;
                debug!("Quic stream sent bytes {} {}", sent, data_sent);
            }
        }

        connection_sent += send(&mut conn, &socket, Some(*destination.addr()))?;

        if conn.is_closed() {
            info!(
                "Client close connection sent {} read {} stats {:?}",
                connection_sent,
                connection_read,
                conn.stats()
            );
            if !conn.is_established() {
                return Err(ConnectionError::Timeout(
                    "quic client packet".to_owned(),
                    now.elapsed(),
                ));
            }
            return Ok(data_sent);
        }
    }
}

pub async fn receive_data(
    socket: Arc<UdpSocket>,
    encryptor: &impl FrameDecryptor,
    private_key: &str,
    public_key: &str,
    max_len: usize,
    timeout_callback: impl Fn(Duration) -> bool,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let mut config = load_server_config(private_key, public_key)?;
    let mut connection_sent = 0;
    let mut received = Vec::new();
    let timeout_with_time = |d: Duration| -> bool {
        timeout_callback(d)
    };

    let (header, addr, mut buffer, mut connection_read) =
        receive_handshake(&socket, encryptor, timeout_with_time).await?;

    debug!(
        "Initial packet with size {} received {:?}",
        connection_read, header
    );

    let mut conn = quiche::accept(&header.scid, Some(&header.dcid), &mut config)?;

    match conn.recv(&mut buffer) {
        Ok(v) => v,
        Err(quiche::Error::Done) => 0,
        Err(e) => {
            error!("Quic error occured while receiving packet {}", e);
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

            if !conn.is_established() {
                return Err(ConnectionError::Timeout(
                    "quic packet".to_owned(),
                    now.elapsed(),
                ));
            }

            return Ok((received, addr));
        }

        if timeout_with_time(now.elapsed()) {
            return Err(ConnectionError::Timeout(
                "quic packet".to_owned(),
                now.elapsed(),
            ));
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
            return Err(ConnectionError::LimitReached {
                received: received.len(),
                max_len,
            });
        }
    }
    Ok(())
}

async fn send_handshake(
    conn: &mut Connection,
    socket: &UdpSocket,
    destination: SocketAddr,
    encryptor: impl FrameEncryptor,
    timeout_callback: impl Fn(Duration) -> bool,
) -> Result<usize, ConnectionError>
{
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let cwrite = conn.send(&mut out)?;
    let enc_write = encryptor.encrypt(out[..cwrite].to_vec(), &MessageType::Handshake, &destination)?;

    let now = Instant::now();
    while !timeout_callback(now.elapsed()) {
        let connection_sent = match timeout(
            Duration::from_millis(100),
            socket.send_to(&enc_write, destination),
        )
        .await
        {
            Ok(v) => v?,
            Err(_) => continue,
        };
        return Ok(connection_sent);
    }
    Err(ConnectionError::FailedToConnect(
        "Quic failed to send initial data".to_owned(),
    ))
}

async fn receive_handshake<'a>(
    socket: &UdpSocket,
    encryptor: &impl FrameDecryptor,
    timeout: impl Fn(Duration) -> bool,
) -> Result<(Header<'a>, SocketAddr, Vec<u8>, usize), ConnectionError>
{
    let mut buffer = [0; MAX_UDP_BUFFER];
    let (connection_read, addr) = receive_from_timeout(socket, &mut buffer, timeout).await?;
    let (mut pkt_buf, _) =
        encryptor.decrypt(buffer[..connection_read].to_vec(), &Identity::from_mapped(&addr))?;
    let header = match Header::from_slice(&mut pkt_buf, quiche::MAX_CONN_ID_LEN) {
        Ok(v) => v,

        Err(e) => {
            error!("Parsing packet header failed: {:?}", e);
            return Err(ConnectionError::InvalidBuffer(
                "Failed to read handshake".into()
            ));
        }
    };

    Ok((header, addr, pkt_buf, connection_read))
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
                return Err(ConnectionError::InvalidBuffer(
                    "Failed to read socket".into()
                ));
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
    Ok(connection_read)
}

fn send(
    conn: &mut Connection,
    socket: &UdpSocket,
    destination: Option<SocketAddr>,
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

        let op = if let Some(addr) = destination {
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
    Ok(connection_sent)
}

fn load_config() -> Result<Config, ConnectionError>
{
    let mut config = Config::new(quiche::PROTOCOL_VERSION)?;
    config
        .set_application_protos(b"\x05hq-29\x05hq-28\x05hq-27\x08http/0.9")
        .unwrap();

    config.set_max_idle_timeout(CONNECTION_TIMEOUT);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE as usize);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_early_data();
    Ok(config)
}

fn load_client_config(verify_path: Option<String>) -> Result<Config, ConnectionError>
{
    let mut config = load_config()?;
    config.verify_peer(true);

    // use custom verify dir
    if let Some(crt_str) = verify_path {
        config
            .load_verify_locations_from_directory(&crt_str)
            .map_err(|e| {
                ConnectionError::InvalidKey(format!(
                    "Verify certificates directory not found {} {}",
                    crt_str, e
                ))
            })?;
    }
    Ok(config)
}

fn load_server_config(key_path: &str, cert_path: &str) -> Result<Config, ConnectionError>
{
    let mut config = load_config()?;
    //@TODO does not work client verification support
    // config.verify_peer(true);
    config
        .load_cert_chain_from_pem_file(cert_path)
        .map_err(|e| {
            ConnectionError::InvalidKey(format!(
                "Certificate not found or not valid {} {}",
                cert_path, e
            ))
        })?;
    config.load_priv_key_from_pem_file(key_path).map_err(|e| {
        ConnectionError::InvalidKey(format!("Key not found or not valid {} {}", key_path, e))
    })?;

    Ok(config)
}

#[cfg(test)]
mod quichetest
{
    use super::*;
    use crate::assert_error_type;
    use crate::encryption::random;
    use crate::fragmenter::{GroupsEncryptor, IdentityEncryptor};
    use crate::message::Group;
    use indexmap::indexmap;
    use tokio::try_join;

    async fn send_receive(size: usize, max_len: usize)
    {
        let local_server: SocketAddr = "127.0.0.1:9956".parse().unwrap();
        let local_client: SocketAddr = "127.0.0.1:9957".parse().unwrap();
        let server_sock = Arc::new(UdpSocket::bind(local_server).await.unwrap());
        let client_sock = Arc::new(UdpSocket::bind(local_client).await.unwrap());

        let group = Group::from_addr("test1", "127.0.0.1:9957", "127.0.0.1:9957");
        let groups = indexmap![group.name.clone() => group.clone()];

        let enc_r = GroupsEncryptor::new(groups);
        let enc_s = IdentityEncryptor::new(group, Identity::from(&local_server));

        let data_sent = random(size);
        let for_sending = data_sent.clone();
        let r = tokio::spawn(async move {
            receive_data(
                server_sock,
                &enc_r,
                "tests/certs/localhost.key",
                "tests/certs/localhost.crt",
                max_len,
                |d: Duration| d > Duration::from_millis(5000),
            )
            .await
        });

        let s = tokio::spawn(async move {
            send_data(
                client_sock,
                enc_s,
                for_sending,
                local_server.into(),
                Some("tests/certs/cert-verify".to_owned()),
                |d: Duration| d > Duration::from_millis(5000),
            )
            .await
        });

        let res = try_join!(r, s).unwrap();

        if size > max_len {
            assert_error_type!(res.0, ConnectionError::LimitReached { .. });
        } else {
            let _data_len_sent = res.1.unwrap();
            let (data_received, addr) = res.0.unwrap();
            assert_eq!(local_client, addr);
            // assert_eq!(data_len_sent, size);
            assert_eq!(data_sent, data_received);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_data()
    {
        send_receive(5, 100).await;
        send_receive(16 * 1024 * 10, 16 * 1024 * 10 + 1000).await;
        send_receive(10, 5).await;
    }

    #[tokio::test]
    async fn test_timeout()
    {
        let local_server: SocketAddr = "127.0.0.1:3985".parse().unwrap();
        let server_sock = Arc::new(UdpSocket::bind(local_server).await.unwrap());

        let group = Group::from_name("test1");
        let groups = indexmap![group.name.clone() => group.clone()];
        let enc_r = GroupsEncryptor::new(groups);

        let result = receive_data(
            server_sock,
            &enc_r,
            "tests/certs/localhost.key",
            "tests/certs/localhost.crt",
            10,
            |_: Duration| true,
        )
        .await;

        assert_error_type!(result, ConnectionError::IoError(..));
    }
}
