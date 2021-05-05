use laminar::{Config, Packet, Socket, SocketEvent};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::thread;
use std::time::Instant;
use tokio::time::Duration;

use crate::defaults::MAX_ENCRYPTION_HEADER_SIZE;
use crate::errors::ConnectionError;
use crate::fragmenter::{size_to_indexes, FrameDecryptor, FrameIndexEncryptor};
use crate::identity::Identity;
use crate::socket::Timeout;

pub async fn receive_data(
    socket: &mut Socket,
    encryptor: &impl FrameDecryptor,
    max_len: usize,
    timeout_callback: impl Timeout,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let mut now = Instant::now();
    let mut received_frames: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut total_size = 0;

    loop {
        socket.manual_poll(Instant::now());
        let result = socket.recv();

        match result {
            Some(socket_event) => match socket_event {
                SocketEvent::Packet(packet) => {
                    now = Instant::now();
                    let addr: SocketAddr = packet.addr();
                    let data: &[u8] = packet.payload();

                    let (frame, _) =
                        encryptor.decrypt_to_frame(data, &Identity::from_addr(&addr))?;
                    total_size += data.len();

                    if total_size > max_len {
                        return Err(ConnectionError::LimitReached(format!(
                            "Received more data {} than expected {}",
                            total_size, max_len
                        )));
                    }

                    received_frames.insert(frame.index, frame.data);

                    if frame.total as usize == received_frames.len() {
                        let mut full = Vec::new();
                        for (_, mut frame) in received_frames {
                            full.append(&mut frame);
                        }
                        return Ok((full, addr));
                    }
                }
                SocketEvent::Timeout(_) => {
                    return Err(ConnectionError::FailedToConnect(
                        "Timeout waiting for data".to_owned(),
                    ));
                }
                SocketEvent::Disconnect(_) => {
                    return Err(ConnectionError::FailedToConnect(
                        "Client disconnected".to_owned(),
                    ));
                }
                SocketEvent::Connect(_) => {
                    continue;
                }
            },
            None => {
                if timeout_callback(now.elapsed()) {
                    return Err(ConnectionError::FailedToConnect(format!(
                        "Timeout. Failed to receive data"
                    )));
                } else {
                    // @TODO laminar and async
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }
}

pub async fn send_data(
    mut socket: Socket,
    config: &Config,
    encryptor: impl FrameIndexEncryptor,
    data: Vec<u8>,
    destination_addr: &SocketAddr,
) -> Result<usize, ConnectionError>
{
    let max_payload = config.max_packet_size - MAX_ENCRYPTION_HEADER_SIZE as usize;
    let indexes = size_to_indexes(data.len(), max_payload);
    let reliable = !destination_addr.ip().is_multicast();
    let mut size = 0;

    for index in 0..indexes {
        let bytes = encryptor.encrypt_with_index(&data, index as u32, max_payload)?;
        size += bytes.len();

        let packet = if reliable {
            Packet::reliable_ordered(destination_addr.clone(), bytes, None)
        } else {
            Packet::unreliable_sequenced(destination_addr.clone(), bytes, None)
        };
        socket.send(packet).map_err(|e| {
            ConnectionError::FailedToConnect(format!(
                "Unable to send to address {} {}",
                destination_addr, e
            ))
        })?;
        socket.manual_poll(Instant::now());
    }

    return Ok(size);
}

pub fn obtain_socket(local_address: &SocketAddr) -> Result<(Socket, Config), ConnectionError>
{
    let config = Config::default();
    let sock = Socket::bind_with_config(local_address, config.clone()).map_err(|e| {
        ConnectionError::FailedToConnect(format!(
            "Unable to bind local address {} {}",
            local_address, e
        ))
    })?;
    return Ok((sock, config));
}

#[cfg(test)]
mod laminartest
{
    use super::*;
    use crate::assert_error_type;
    use crate::encryption::random;
    use crate::fragmenter::{GroupsEncryptor, IdentityEncryptor};
    use crate::message::Group;
    use futures::try_join;

    async fn send_receive(size: usize, max_len: usize)
    {
        let local_server: SocketAddr = "127.0.0.1:39835".parse().unwrap();
        let local_client: SocketAddr = "127.0.0.1:39836".parse().unwrap();
        let mut server_sock = Socket::bind(local_server).unwrap();
        let client_sock = Socket::bind(local_client).unwrap();

        let data_sent = random(size);
        let for_sending = data_sent.clone();

        let group = Group::from_name("test1");
        let groups = vec![group.clone()];

        let enc_r = GroupsEncryptor::new(groups);
        let enc_s = IdentityEncryptor::new(group, Identity::from_addr(&local_server));

        let config = Config::default();

        let res = try_join!(
            tokio::spawn(async move {
                receive_data(&mut server_sock, &enc_r, max_len, |d: Duration| {
                    d > Duration::from_millis(2000)
                })
                .await
            }),
            tokio::spawn(async move {
                send_data(client_sock, &config, enc_s, for_sending, &local_server).await
            }),
        )
        .unwrap();

        if size > max_len {
            assert_error_type!(res.0, ConnectionError::LimitReached(_));
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
}
