use crossbeam_channel::{Receiver, Sender};
use laminar::{Config, Packet, Socket, SocketEvent};
use log::debug;
use std::collections::BTreeMap;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use tokio::sync::Mutex;
use tokio::time::Duration;

use crate::defaults::MAX_ENCRYPTION_HEADER_SIZE;
use crate::errors::ConnectionError;
use crate::fragmenter::{size_to_indexes, FrameDecryptor, FrameIndexEncryptor};
use crate::identity::Identity;

pub struct LaminarSocket
{
    sender: Sender<Packet>,
    receiver: Receiver<SocketEvent>,
    socket: Arc<Mutex<Socket>>,
    config: Config,
}

impl LaminarSocket
{
    pub fn get_sender(&self) -> LaminarSender
    {
        LaminarSender {
            sender: self.sender.clone(),
            config: self.config.clone(),
            socket: Arc::clone(&self.socket),
        }
    }

    pub fn get_receiver(&self) -> LaminarReceiver
    {
        LaminarReceiver {
            receiver: self.receiver.clone(),
            config: self.config.clone(),
            socket: Arc::clone(&self.socket),
        }
    }
}

pub struct LaminarReceiver
{
    pub receiver: Receiver<SocketEvent>,
    pub config: Config,
    socket: Arc<Mutex<Socket>>,
}

pub struct LaminarSender
{
    pub sender: Sender<Packet>,
    pub config: Config,
    socket: Arc<Mutex<Socket>>,
}

impl LaminarReceiver
{
    pub async fn recv(&self) -> Option<SocketEvent>
    {
        self.socket.lock().await.manual_poll(Instant::now());
        self.receiver.try_recv().ok()
    }
}

impl LaminarSender
{
    pub async fn send(&self, packet: Packet) -> bool
    {
        let result = self.sender.send(packet);
        self.socket.lock().await.manual_poll(Instant::now());
        result.is_ok()
    }
}

pub fn run_laminar(local_address: &SocketAddr) -> Result<LaminarSocket, ConnectionError>
{
    let (socket, config) = obtain_socket(local_address)?;
    let sender = socket.get_packet_sender();
    let receiver = socket.get_event_receiver();
    // @TODO doest not work
    // let thread = tokio::spawn(async move {
    //     while trunning.load(Ordering::Relaxed) {
    //         socket.manual_poll(Instant::now());
    //         sleep(sleep_duration).await;
    //     }
    // });
    Ok(LaminarSocket {
        sender,
        receiver,
        config,
        socket: Arc::new(Mutex::new(socket)),
    })
}

pub async fn receive_data(
    socket: &LaminarReceiver,
    encryptor: &impl FrameDecryptor,
    max_len: usize,
    timeout_callback: impl Fn(Duration) -> bool,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let mut now = Instant::now();
    let mut received_frames: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut total_size = 0;

    loop {
        let result = socket.recv().await;

        match result {
            Some(socket_event) => match socket_event {
                SocketEvent::Packet(packet) => {
                    now = Instant::now();
                    let addr: SocketAddr = packet.addr();
                    let data: &[u8] = packet.payload();

                    let (frame, _) =
                        encryptor.decrypt_to_frame(data.to_vec(), &Identity::from_mapped(&addr))?;
                    total_size += data.len();

                    if total_size > max_len {
                        return Err(ConnectionError::LimitReached {
                            received: total_size,
                            max_len,
                        });
                    }

                    debug!(
                        "Received frame index {} out of {}",
                        frame.index, frame.total
                    );

                    received_frames.entry(frame.index).or_insert(frame.data);

                    if frame.total as usize == received_frames.len() {
                        let mut full = Vec::new();
                        for (_, mut frame) in received_frames {
                            full.append(&mut frame);
                        }
                        return Ok((full, addr));
                    }
                }
                SocketEvent::Timeout(_) => {
                    if total_size == 0 {
                        return Err(ConnectionError::IoError(Error::new(
                            ErrorKind::TimedOut,
                            "laminar timeout".to_string(),
                        )));
                    }
                    return Err(ConnectionError::Timeout(
                        "laminar received".to_owned(),
                        now.elapsed(),
                    ));
                }
                SocketEvent::Disconnect(_) => {
                    if total_size == 0 {
                        return Err(ConnectionError::IoError(Error::new(
                            ErrorKind::TimedOut,
                            "laminar disconnect".to_string(),
                        )));
                    }
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
                    return Err(ConnectionError::Timeout(
                        "laminar none received".to_owned(),
                        now.elapsed(),
                    ));
                } else {
                    // @TODO laminar and async
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }
}

pub async fn send_data(
    socket: &LaminarSender,
    encryptor: impl FrameIndexEncryptor,
    data: Vec<u8>,
    destination_addr: &SocketAddr,
) -> Result<usize, ConnectionError>
{
    let max_payload = socket.config.max_packet_size - MAX_ENCRYPTION_HEADER_SIZE as usize;
    let indexes = size_to_indexes(data.len(), max_payload);
    let reliable = !destination_addr.ip().is_multicast();
    let mut size = 0;

    for index in 0..indexes {
        let bytes =
            encryptor.encrypt_with_index(&data, index as u32, max_payload, destination_addr)?;
        size += bytes.len();

        debug!("Send index {} bytes {}", index, bytes.len());

        let packet = if reliable {
            Packet::reliable_ordered(*destination_addr, bytes, None)
        } else {
            Packet::unreliable_sequenced(*destination_addr, bytes, None)
        };
        if !socket.send(packet).await {
            return Err(ConnectionError::FailedToConnect(format!(
                "Unable to send to address {}",
                destination_addr
            )));
        }
    }

    Ok(size)
}

pub fn obtain_socket(local_address: &SocketAddr) -> Result<(Socket, Config), ConnectionError>
{
    let config = Config {
        fragment_reassembly_buffer_size: 1024,
        ..Default::default()
    };
    let sock = Socket::bind_with_config(local_address, config.clone()).map_err(|e| {
        ConnectionError::FailedToConnect(format!(
            "Unable to bind local address {} {}",
            local_address, e
        ))
    })?;
    Ok((sock, config))
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
    use indexmap::indexmap;

    async fn send_receive(size: usize, max_len: usize)
    {
        let local_server: SocketAddr = "127.0.0.1:39835".parse().unwrap();
        let local_client: SocketAddr = "127.0.0.1:39836".parse().unwrap();
        let server_sock = run_laminar(&local_server).unwrap();
        let client_sock = run_laminar(&local_client).unwrap();

        let data_sent = random(size);
        let for_sending = data_sent.clone();

        let group = Group::from_addr("test1", "127.0.0.1:39836", "127.0.0.1:39836");
        let groups = indexmap! {group.name.clone() => group.clone()};
        let enc_r = GroupsEncryptor::new(groups);
        let enc_s = IdentityEncryptor::new(group, Identity::from(&local_server));

        let res = try_join!(
            tokio::spawn(async move {
                receive_data(
                    &server_sock.get_receiver(),
                    &enc_r,
                    max_len,
                    |d: Duration| d > Duration::from_millis(4000),
                )
                .await
            }),
            tokio::spawn(async move {
                send_data(&client_sock.get_sender(), enc_s, for_sending, &local_server).await
            }),
        )
        .unwrap();

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
        send_receive(16 * 1024 * 10, 16 * 1024 * 10 + 1200).await;
        send_receive(10, 5).await;
    }

    #[tokio::test]
    async fn test_timeout()
    {
        let local_server: SocketAddr = "127.0.0.1:3835".parse().unwrap();
        let server_sock = run_laminar(&local_server).unwrap();

        let group = Group::from_name("test1");
        let groups = indexmap! {group.name.clone() => group.clone()};
        let enc_r = GroupsEncryptor::new(groups);

        let result =
            receive_data(&server_sock.get_receiver(), &enc_r, 10, |_: Duration| true).await;

        assert_error_type!(result, ConnectionError::Timeout(..));
    }
}
