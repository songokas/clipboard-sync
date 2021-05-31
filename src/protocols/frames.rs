use flume::{bounded, Receiver, Sender};
use log::{debug, error, warn};
use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};
use tokio::try_join;

use crate::defaults::{CONNECTION_TIMEOUT, MAX_UDP_BUFFER, MAX_UDP_PAYLOAD};
use crate::encryption::DataEncryptor;
use crate::errors::ConnectionError;
use crate::fragmenter::{
    size_to_indexes, FrameDataDecryptor, FrameDecryptor, FrameEncryptor, FrameIndexEncryptor,
};
use crate::identity::Identity;
use crate::message::MessageType;
use crate::socket::receive_from_timeout;

pub async fn receive_data(
    socket: Arc<UdpSocket>,
    encryptor: &(impl FrameDecryptor + DataEncryptor),
    max_len: usize,
    timeout: impl Fn(Duration) -> bool,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let mut received_frames: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut data = [0; MAX_UDP_BUFFER];
    let mut received = 0;
    let mut last_addr: Option<SocketAddr> = None;
    let timeout_callback_with_time = |d: Duration| -> bool {
        return d > Duration::from_millis(CONNECTION_TIMEOUT) || timeout(d);
    };

    loop {
        let (read, addr) =
            receive_from_timeout(&socket, &mut data, timeout_callback_with_time).await?;

        received += read;

        if received > max_len {
            return Err(ConnectionError::LimitReached { received, max_len });
        }

        if last_addr.is_none() {
            last_addr = Some(addr);
        }

        if last_addr.expect("No previous socket address exist") != addr {
            return Err(ConnectionError::InvalidBuffer(
                "Received data from different address".to_owned(),
            ));
        }

        let identity = Identity::from_mapped(&addr);

        let (frame, group) = encryptor.decrypt_to_frame(&data, &identity)?;

        debug!(
            "Read {} bytes from {}, index {} total {}",
            read, addr, frame.index, frame.total
        );

        received_frames.entry(frame.index).or_insert(frame.data);

        let confirm_bytes = encryptor.encrypt(
            &frame.index.to_be_bytes(),
            &group,
            &identity,
            &MessageType::Frame,
        )?;

        socket.send_to(&confirm_bytes, addr).await?;

        if frame.total as usize == received_frames.len() {
            let mut full = Vec::new();
            for (_, mut frame) in received_frames {
                full.append(&mut frame);
            }
            return Ok((full, addr));
        }
    }
}

pub async fn send_data(
    socket: Arc<UdpSocket>,
    encryptor: impl FrameEncryptor
        + FrameDataDecryptor
        + FrameIndexEncryptor
        + Send
        + Sync
        + Clone
        + 'static,
    data: Vec<u8>,
    destination: SocketAddr,
    timeout_callback: impl Fn(Duration) -> bool + std::marker::Sync + std::marker::Send + 'static,
) -> Result<usize, ConnectionError>
{
    let indexes = size_to_indexes(data.len(), MAX_UDP_PAYLOAD);

    let socket_writer = Arc::clone(&socket);
    let socket_reader = Arc::clone(&socket_writer);
    let indexes_b = indexes.clone();
    // let confirm_timeout = |d: Duration| timeout_callback(d);
    let (channel_sender, channel_receiver) = bounded(indexes * 4);
    let res = try_join!(
        tokio::spawn(confirm_received(
            socket_reader,
            channel_sender,
            encryptor.clone(),
            indexes_b,
        )),
        tokio::spawn(confirm_sent(
            socket_writer,
            channel_receiver,
            encryptor.clone(),
            data,
            destination,
            indexes,
            timeout_callback,
        ))
    )
    .map_err(ConnectionError::JoinError)?;
    return Ok(res.1?);
}

async fn confirm_received(
    socket_reader: Arc<UdpSocket>,
    channel_sender: Sender<u32>,
    encryptor: impl FrameDataDecryptor,
    indexes: usize,
) -> Result<usize, ConnectionError>
{
    let mut received: HashMap<u32, bool> = HashMap::new();
    let timeout_callback_with_channel = |d: Duration| -> bool {
        return d > Duration::from_millis(CONNECTION_TIMEOUT) || channel_sender.is_disconnected();
    };
    while received.len() != indexes && !channel_sender.is_disconnected() {
        let mut bytes = [0; 100];
        let received_bytes =
            match receive_from_timeout(&socket_reader, &mut bytes, timeout_callback_with_channel)
                .await
            {
                Ok(_) => encryptor.decrypt(&bytes),
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

        // debug!("Received frame confirmation {}", index);

        if (index as usize) < indexes {
            received.insert(index, true);
            if let Err(e) = channel_sender.try_send(index) {
                error!("Failed to send index {} to channel {}", index, e);
            }
        }
    }
    return Ok(received.len());
}

async fn confirm_sent(
    socket_writer: Arc<UdpSocket>,
    channel_receiver: Receiver<u32>,
    encryptor: impl FrameIndexEncryptor,
    data: Vec<u8>,
    destination: SocketAddr,
    indexes: usize,
    timeout: impl Fn(Duration) -> bool,
) -> Result<usize, ConnectionError>
{
    let mut sent_without_confirmation: HashMap<u32, bool> = HashMap::new();
    let mut i: u32 = 0;
    let mut sent = 0;
    // first send all
    while i < indexes as u32 {
        sent += send_index(&socket_writer, &encryptor, &data, &destination, i).await?;
        sent_without_confirmation.insert(i, true);
        i += 1;
        sleep(Duration::from_millis(10)).await;
    }
    let now = Instant::now();
    let timeout_with_time = |d: Duration| -> bool {
        return d > Duration::from_millis(CONNECTION_TIMEOUT) || timeout(d);
    };

    while sent_without_confirmation.len() > 0 {
        sleep(Duration::from_millis(100)).await;
        while i < 5000 && sent_without_confirmation.len() > 0 {
            if let Ok(index) = channel_receiver.try_recv() {
                if let None = sent_without_confirmation.remove(&index) {
                    error!("Error frame index {} does not exist", index);
                }
            }
            i += 1;
        }

        for (index, _) in sent_without_confirmation.iter() {
            sent += send_index(
                &socket_writer,
                &encryptor,
                &data,
                &destination,
                index.clone(),
            )
            .await?;
        }
        if timeout_with_time(now.elapsed()) {
            return Err(ConnectionError::FailedToConnect(format!(
                "Connection timeout {}. Total {} Remaining {}",
                now.elapsed().as_millis(),
                indexes,
                sent_without_confirmation.len()
            )));
        }
    }
    return Ok(sent);
}

async fn send_index(
    socket_writer: &UdpSocket,
    encryptor: &impl FrameIndexEncryptor,
    data: &[u8],
    destination: &SocketAddr,
    index: u32,
) -> Result<usize, ConnectionError>
{
    let bytes = encryptor.encrypt_with_index(data, index, MAX_UDP_PAYLOAD)?;

    // debug!("Sent frame {} with {} bytes", index, bytes.len());

    return match socket_writer.send_to(&bytes, destination).await {
        Ok(n) => Ok(n),
        Err(e) => Err(ConnectionError::FailedToConnect(format!(
            "Failed to send index {}. Message: {}",
            index, e
        ))),
    };
}

#[cfg(test)]
mod framestest
{
    use super::*;
    use crate::assert_error_type;
    use crate::encryption::random;
    use crate::fragmenter::{GroupsEncryptor, IdentityEncryptor};
    use crate::message::Group;
    use futures::try_join;
    use indexmap::indexmap;

    async fn test_send_receive(
        data_len: usize,
        max_len: usize,
        port: u32,
    ) -> (
        SocketAddr,
        Vec<u8>,
        (
            Result<usize, ConnectionError>,
            Result<(Vec<u8>, SocketAddr), ConnectionError>,
        ),
    )
    {
        // env_logger::from_env(env_logger::Env::default().default_filter_or("debug")).init();
        let client_str = format!("127.0.0.1:993{}", port + 1);
        let local_server: SocketAddr = format!("127.0.0.1:993{}", port).parse().unwrap();
        let local_client: SocketAddr = client_str.parse().unwrap();
        let server_sock = Arc::new(UdpSocket::bind(local_server).await.unwrap());
        let client_sock = Arc::new(UdpSocket::bind(local_client).await.unwrap());
        let group = Group::from_addr("test1", &client_str, &client_str);
        let groups = indexmap! {group.name.clone() => group.clone()};

        let enc_r = GroupsEncryptor::new(groups);
        let enc_s = IdentityEncryptor::new(group, Identity::from(&local_server));

        client_sock.connect(local_server).await.unwrap();

        let data_sent = random(data_len);
        let expected_data = data_sent.clone();
        let res = try_join!(
            tokio::spawn(async move {
                send_data(
                    client_sock,
                    enc_s,
                    data_sent,
                    local_server,
                    |d: Duration| d > Duration::from_millis(2000),
                )
                .await
            }),
            tokio::spawn(async move {
                receive_data(server_sock, &enc_r, max_len, |d: Duration| {
                    d > Duration::from_millis(2000)
                })
                .await
            })
        )
        .unwrap();
        return (local_client, expected_data, res);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_send_receive_more_data()
    {
        let (_, _, res) = test_send_receive(100, 100, 4).await;
        assert_error_type!(res.0, ConnectionError::FailedToConnect(_));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_send_receive_10mb()
    {
        let data_len = 10 * 1024 * 1024;
        let max_len = data_len + 20000;
        let (local_client, expected_data, res) = test_send_receive(data_len, max_len, 6).await;
        let data_len_sent = res.0.unwrap();
        let (data_received, addr) = res.1.unwrap();

        assert_eq!(local_client, addr);
        assert_eq!(data_len_sent, 10501530);
        assert_eq!(expected_data.len(), data_received.len());
        assert_eq!(expected_data, data_received);
    }

    #[tokio::test]
    async fn test_timeout()
    {
        let local_server: SocketAddr = "127.0.0.1:3987".parse().unwrap();
        let server_sock = Arc::new(UdpSocket::bind(local_server).await.unwrap());
        let group = Group::from_name("test1");
        let groups = indexmap! {group.name.clone() => group.clone()};

        let enc_r = GroupsEncryptor::new(groups);
        let result = receive_data(server_sock, &enc_r, 10, |_: Duration| true).await;

        assert_error_type!(result, ConnectionError::IoError(_));
    }
}
