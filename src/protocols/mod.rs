use bytes::Bytes;
use core::time::Duration;
use indexmap::IndexSet;
use std::net::SocketAddr;

pub mod basic;
#[cfg(feature = "quic")]
pub mod quic;
pub mod tcp;
#[cfg(feature = "tls")]
pub mod tcp_tls;

use crate::identity::Identity;
use crate::message::{GroupName, MessageType};

pub struct ProtocolReadMessage {
    pub group: GroupName,
    pub message_type: MessageType,
    pub remote: Identity,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct ProtocolWriteMessage {
    pub group: GroupName,
    pub local_addresses: IndexSet<SocketAddr>,
    pub destination: String,
    pub server_name: Option<String>,
    pub message_type: MessageType,
    pub heartbeat: Option<Duration>,
    pub data: Bytes,
}

pub enum StatusMessage {
    Ok(StatusInfo),
    Err(String),
}

impl StatusMessage {
    pub fn from_err(error: impl Into<String>) -> Self {
        Self::Err(error.into())
    }
}

pub struct StatusInfo {
    pub message_type: MessageType,
    pub data_size: usize,
    pub destination: String,
    pub status_handler: StatusHandler,
}

impl StatusInfo {
    pub fn into_ok(self) -> StatusMessage {
        StatusMessage::Ok(self)
    }
}

pub enum StatusHandler {
    Filesystem,
    Clipboard,
    Protocol,
}

#[cfg(test)]
mod helpers {

    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::net::UdpSocket;

    use super::*;
    use crate::encryption::random;
    use crate::errors::CliError;
    use crate::message::MessageType;
    use crate::message::SendGroup;
    use tokio::sync::mpsc::Receiver;
    use tokio::sync::mpsc::Sender;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    #[allow(clippy::too_many_arguments)]
    pub async fn send_and_verify_test_data(
        sample: serde_json::Value,
        receiver_result: JoinHandle<Result<(&'static str, u64), CliError>>,
        sender_result: JoinHandle<Result<(&'static str, u64), CliError>>,
        writer_sender: Sender<ProtocolWriteMessage>,
        mut reader_receiver: Receiver<ProtocolReadMessage>,
        mut status_receiver: Receiver<StatusMessage>,
        cancel: CancellationToken,
        group: SendGroup,
    ) {
        let mut data_sample: HashMap<String, Vec<u8>> = HashMap::new();

        let random1 = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let random2 = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        for send in sample["send"]["messages"].as_array().unwrap() {
            let data = random(send["data_length"].as_u64().unwrap() as usize);
            data_sample.insert(send["data_id"].as_str().unwrap().to_string(), data);
        }

        for send in sample["send"]["messages"].as_array().unwrap() {
            let local_addresses = send["bind_address"]
                .as_str()
                .unwrap()
                .split(',')
                .map(|s| {
                    let s = s.replace("{RANDOM1}", &random1.to_string());
                    let s = s.replace("{RANDOM2}", &random2.to_string());
                    s.parse().unwrap()
                })
                .collect();
            timeout(
                Duration::from_millis(5000),
                writer_sender.send(ProtocolWriteMessage {
                    group: group.name.clone(),
                    local_addresses,
                    destination: send["destination"].as_str().unwrap().to_string(),
                    server_name: send["server_name"].as_str().map(ToString::to_string),
                    message_type: MessageType::Handshake,
                    heartbeat: None,
                    data: Bytes::from(data_sample[send["data_id"].as_str().unwrap()].clone()),
                }),
            )
            .await
            .unwrap()
            .unwrap();
        }

        let mut expected = HashSet::new();
        let mut received = HashSet::new();
        for message in sample["send"]["messages"].as_array().unwrap() {
            if let Some(false) = message["verify_sent"].as_bool() {
                continue;
            }
            expected.insert(data_sample[message["data_id"].as_str().unwrap()].len());
            let sent_bytes = timeout(Duration::from_millis(15000), status_receiver.recv())
                .await
                .unwrap()
                .unwrap();
            let sent_bytes = match sent_bytes {
                StatusMessage::Ok(s) => s,
                StatusMessage::Err(e) => panic!("Unexpected error {e}"),
            };
            received.insert(sent_bytes.data_size);
        }

        assert_eq!(expected, received);

        let mut expected = HashMap::new();
        let mut received = HashMap::new();

        for message in sample["receive"]["messages"].as_array().unwrap() {
            let pmessage = timeout(Duration::from_millis(15000), reader_receiver.recv())
                .await
                .unwrap()
                .unwrap();
            let expected_data = data_sample[message["data_id"].as_str().unwrap()].clone();
            expected.insert(expected_data.len(), expected_data);
            received.insert(pmessage.data.len(), pmessage.data);
        }
        assert_eq!(expected, received);

        cancel.cancel();
        drop(writer_sender);
        let result = sender_result.await.unwrap().unwrap();
        assert_eq!(sample["send"]["success_count"].as_u64().unwrap(), result.1);
        let result = receiver_result.await.unwrap().unwrap();
        assert_eq!(
            sample["receive"]["success_count"].as_u64().unwrap(),
            result.1
        );
    }
}
