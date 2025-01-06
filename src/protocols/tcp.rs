use bytes::Bytes;
use core::time::Duration;
use log::debug;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::select;

use tokio::time::timeout;
use tokio_util::bytes::BufMut;

use crate::errors::ConnectionError;
use crate::socket::IpAddrExt;
use crate::stream::{receive_stream, send_stream, ReadStream, WriteStream};

pub async fn tcp_receive(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    max_len: usize,
    timeout: Duration,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError> {
    debug!("Tcp connect receive stream local_addr={local_addr} remote_addr={remote_addr}",);

    let timeout_callback = |d: Duration| d > timeout;

    let stream = select! {
        // biased;
        Ok(stream) = listen_stream(local_addr, timeout_callback) => Ok(stream),
        Ok(stream) = connect_stream(local_addr, remote_addr) => Ok(stream),
        else => Err(ConnectionError::Timeout("basic receive", timeout)),
    }?;
    verify_peer(&stream, remote_addr)?;
    let (mut reader, _w) = stream.into_split();
    let bytes = receive_stream(&mut reader, max_len, timeout).await?;
    Ok((bytes, remote_addr))
}

pub async fn tcp_send(
    local_addr: SocketAddr,
    data: Bytes,
    remote_addr: SocketAddr,
    timeout: Duration,
) -> Result<usize, ConnectionError> {
    debug!("Tcp connect send stream local_addr={local_addr} remote_addr={remote_addr}");

    let timeout_callback = |d: Duration| d > timeout;

    let stream = select! {
        // biased;
        Ok(stream) = connect_stream(local_addr, remote_addr) => Ok(stream),
        Ok(stream) = listen_stream(local_addr, timeout_callback) => Ok(stream),
        else => Err(ConnectionError::Timeout("basic send", timeout)),
    }?;

    verify_peer(&stream, remote_addr)?;
    let (_r, mut writer) = stream.into_split();
    let total_sent = send_stream(&mut writer, data).await?;
    Ok(total_sent)
}

pub async fn listen_stream(
    local_addr: SocketAddr,
    timeout_callback: impl Fn(Duration) -> bool,
) -> Result<TcpStream, ConnectionError> {
    let listener = crate::protocols::tcp::obtain_server_socket(local_addr)?;
    let now = Instant::now();
    while !timeout_callback(now.elapsed()) {
        let (stream, _) = match timeout(Duration::from_millis(100), listener.accept()).await {
            Ok(v) => v?,
            Err(_) => continue,
        };
        return Ok(stream);
    }
    Err(ConnectionError::Timeout(
        "basic listen stream",
        now.elapsed(),
    ))
}

pub fn verify_peer(stream: &TcpStream, expected_peer: SocketAddr) -> Result<bool, ConnectionError> {
    match stream.peer_addr() {
        Ok(a) => {
            if expected_peer.ip().is_multicast() && !IpAddrExt::is_global(&a.ip()) {
                return Ok(true);
            }
            if a != expected_peer {
                return Err(ConnectionError::InvalidSource(a));
            }
            Ok(true)
        }
        _ => Err(ConnectionError::NoSourceIp),
    }
}

pub fn obtain_client_socket(local_addr: SocketAddr) -> Result<TcpSocket, ConnectionError> {
    let socket = if local_addr.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    socket.set_reuseaddr(true)?;
    #[cfg(not(target_os = "windows"))]
    socket.set_reuseport(true)?;
    socket
        .bind(local_addr)
        .map_err(|e| ConnectionError::BindError(local_addr, e))?;
    Ok(socket)
}

pub fn obtain_server_socket(local_addr: SocketAddr) -> Result<TcpListener, ConnectionError> {
    let socket = obtain_client_socket(local_addr)?;
    let listener = socket.listen(1024)?;
    Ok(listener)
}

pub async fn connect_stream(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> Result<TcpStream, ConnectionError> {
    let socket = obtain_client_socket(local_addr)?;
    let stream = socket.connect(remote_addr).await?;
    Ok(stream)
}

impl ReadStream for OwnedReadHalf {
    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.local_addr()
    }

    fn peer_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.peer_addr()
    }

    async fn read_buffer(&mut self, buffer: &mut impl BufMut) -> Result<usize, std::io::Error> {
        self.read_buf(buffer).await
    }

    async fn readable_stream(&mut self) -> Result<(), std::io::Error> {
        self.readable().await
    }
}

impl WriteStream for OwnedWriteHalf {
    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.local_addr()
    }

    fn peer_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.peer_addr()
    }

    async fn write_buffer(&mut self, buffer: &[u8]) -> Result<usize, std::io::Error> {
        self.write(buffer).await
    }

    async fn writable_stream(&mut self) -> Result<(), std::io::Error> {
        self.writable().await
    }
}

pub async fn is_closed(socket: &OwnedWriteHalf) -> bool {
    let Ok(Ok(r)) = timeout(Duration::from_millis(100), socket.ready(Interest::READABLE)).await
    else {
        return false;
    };
    r.is_read_closed()
}

#[cfg(test)]
mod tcptest {
    use super::*;
    use crate::message::SendGroup;
    use crate::pools::tcp_stream_pool::TcpStreamPool;
    use crate::protocol_readers::tcp::create_tcp_reader;
    use crate::protocol_writers::tcp::tcp_writer_executor;
    use crate::{encryptor::GroupEncryptor, protocol_readers::ReceiverConfig};
    use indexmap::indexmap;
    use serial_test::serial;
    use tokio::sync::mpsc::channel;
    use tokio_util::sync::CancellationToken;

    async fn send_receive(sample: serde_json::Value) {
        let group =
            SendGroup::from_addr("test1", sample["receive"]["allowed_host"].as_str().unwrap());
        let max_length = sample["receive"]["max_length"].as_u64().unwrap() as usize;

        let groups = indexmap! {group.name.clone() => group.clone()};
        let sender_encryptor = GroupEncryptor::new(groups.clone());
        let receiver_encryptor = GroupEncryptor::new(groups);

        let (reader_sender, reader_receiver) = channel(10);
        let (writer_sender, writer_receiver) = channel(10);
        let (status_sender, status_receiver) = channel(10);
        let cancel: CancellationToken = CancellationToken::new();
        let scancel = cancel.clone();

        let local_server: SocketAddr = sample["receive"]["bind_address"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let stream_pool = TcpStreamPool::default();
        let spool = stream_pool.clone();

        let receiver_config = ReceiverConfig {
            local_addr: local_server,
            max_len: max_length,
            cancel: scancel,
            multicast_ips: Default::default(),
            max_connections: 5,
            multicast_local_addr: None,
        };

        let receiver_result = tokio::spawn(async move {
            create_tcp_reader(reader_sender, receiver_encryptor, spool, receiver_config).await
        });
        let sender_result = tokio::spawn(async move {
            tcp_writer_executor(
                writer_receiver,
                status_sender,
                sender_encryptor,
                stream_pool,
            )
            .await
        });

        crate::protocols::helpers::send_and_verify_test_data(
            sample,
            receiver_result,
            sender_result,
            writer_sender,
            reader_receiver,
            status_receiver,
            cancel,
            group,
        )
        .await;
    }

    #[tokio::test]
    #[serial]
    async fn test_data() {
        // env_logger::from_env(env_logger::Env::default().default_filter_or("debug")).init();
        let samples = [
            include_str!("../../tests/testing_data/bytes.json"),
            include_str!("../../tests/testing_data/kbytes.json"),
            include_str!("../../tests/testing_data/mbytes.json"),
        ];
        for s in samples {
            let value = serde_json::from_str(s).unwrap();
            send_receive(value).await;
        }
    }
}
