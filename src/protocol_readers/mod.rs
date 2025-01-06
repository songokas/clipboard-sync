use core::net::IpAddr;
use indexmap::IndexSet;
use log::{debug, error, info};
use std::net::SocketAddr;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;

pub mod basic;
#[cfg(feature = "quic")]
pub mod quic;
pub mod tcp;
#[cfg(feature = "tls")]
pub mod tcp_tls;

use crate::encryptor::MessageDecryptor;
use crate::errors::ConnectionError;
use crate::protocols::ProtocolReadMessage;

pub struct StreamReceiveError {
    error: ConnectionError,
    remote_addr: SocketAddr,
}

#[derive(Clone)]
pub struct ReceiverConfig {
    pub local_addr: SocketAddr,
    pub max_len: usize,
    pub cancel: CancellationToken,
    pub multicast_ips: IndexSet<IpAddr>,
    pub max_connections: usize,
    pub multicast_local_addr: Option<SocketAddr>,
}

type ReceiveFinishedResult<T> =
    Result<Result<(T, Vec<u8>, SocketAddr), StreamReceiveError>, tokio::task::JoinError>;

async fn process_receive_stream_result<T, D>(
    stream_finished: ReceiveFinishedResult<T>,
    decryptor: &D,
    sender: &Sender<ProtocolReadMessage>,
) -> Result<(T, SocketAddr), Option<SocketAddr>>
where
    D: MessageDecryptor,
{
    match stream_finished {
        Ok(Ok((_stream, data, remote_addr))) if data.is_empty() => {
            debug!("Stream finished remote_addr={remote_addr}");
            Err(remote_addr.into())
        }
        Ok(Ok((stream, data, remote_addr))) => {
            match decryptor.decrypt_message(data, remote_addr.into()) {
                Ok(message) => {
                    debug!(
                        "Message received data_size={} group={} message_type={}",
                        message.data.len(),
                        message.group,
                        message.message_type
                    );
                    if let Err(e) = sender.send(message).await {
                        info!("Unable to send more messages {e}");
                        return Err(None);
                    }
                    Ok((stream, remote_addr))
                }
                Err(e) => {
                    error!("Failed to decrypt data: {e}");
                    Err(remote_addr.into())
                }
            }
        }
        Ok(Err(e)) => {
            let error = &e.error;
            if error.is_closed() {
                debug!("Receiver connection closed: {error}");
            } else {
                error!("Receiver stream error: {error}");
            }
            Err(e.remote_addr.into())
        }
        Err(e) => {
            error!("Join error {e}");
            Err(None)
        }
    }
}
