use bytes::{BufMut, Bytes, BytesMut};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::Duration;

use crate::defaults::MAX_UDP_PAYLOAD;
use crate::errors::ConnectionError;

use super::tcp::tcp_send;

pub async fn send_data(
    socket: &UdpSocket,
    data: Bytes,
    remote_addr: SocketAddr,
    tcp_timeout: Duration,
) -> Result<usize, ConnectionError> {
    let local_addr = socket.local_addr()?;
    let err = |e| {
        ConnectionError::FailedToConnect(format!(
            "Failed to send udp packet local_addr={local_addr} remote_addr={remote_addr} error={e}",
        ))
    };
    if data.len() > MAX_UDP_PAYLOAD {
        socket.send_to(b"1", remote_addr).await.map_err(err)?;
        return tcp_send(local_addr, data, remote_addr, tcp_timeout).await;
    }
    let mut bytes = BytesMut::new();
    bytes.put_u64(data.len() as u64);
    bytes.put(data);
    let data: Bytes = bytes.into();
    // let size_indication = (data.len() as u64).to_be_bytes().to_vec();
    // let data = [size_indication, data].concat();
    socket.send_to(&data, remote_addr).await.map_err(err)
}

pub async fn obtain_server_socket(local_addr: SocketAddr) -> Result<UdpSocket, ConnectionError> {
    let socket = UdpSocket::bind(local_addr).await?;
    Ok(socket)
}

pub async fn obtain_client_socket(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> Result<UdpSocket, ConnectionError> {
    let socket = obtain_server_socket(local_addr).await?;

    if remote_addr.ip().is_multicast() {
        socket.set_multicast_loop_v4(false).unwrap_or(());
        socket.set_multicast_loop_v6(false).unwrap_or(());
    }
    Ok(socket)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::encryptor::GroupEncryptor;
    use crate::message::SendGroup;
    use crate::pools::udp_pool::UdpSocketPool;
    use crate::protocol_readers::basic::create_basic_reader;
    use crate::protocol_writers::basic::basic_writer_executor;
    use indexmap::{indexmap, IndexSet};
    use serial_test::serial;
    use tokio::spawn;
    use tokio::sync::mpsc::channel;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    #[ignore]
    async fn test_reuse_socket_behavior() {
        let local_addr = "127.0.0.1:23301".parse().unwrap();
        let local_addr_unspecified = "0.0.0.0:23301".parse().unwrap();
        let remote_addr = "127.0.0.1:23302".parse().unwrap();
        let socket1 = obtain_client_socket(local_addr_unspecified, remote_addr)
            .await
            .unwrap();
        let socket2 = obtain_client_socket(local_addr, remote_addr).await.unwrap();
        let socket3 = obtain_client_socket(remote_addr, remote_addr)
            .await
            .unwrap();
        socket1.connect(remote_addr).await.unwrap();
        let handle1 = spawn(async move {
            let mut buf = [0; 100];
            timeout(Duration::from_millis(1500), socket1.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap()
        });
        let handle2 = spawn(async move {
            let mut buf = [0; 100];
            timeout(Duration::from_millis(1500), socket2.recv_from(&mut buf))
                .await
                .unwrap()
        });
        socket3.send_to(b"hello", local_addr).await.unwrap();
        let (size, _) = handle1.await.unwrap();
        assert_eq!(5, size);
        assert!(handle2.await.is_err());
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

    async fn send_receive(sample: serde_json::Value) {
        let group =
            SendGroup::from_addr("test1", sample["receive"]["allowed_host"].as_str().unwrap());
        let max_length = sample["receive"]["max_length"].as_u64().unwrap() as usize;

        let udp_pool = UdpSocketPool::default();
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

        let receiver_result = tokio::spawn(create_basic_reader(
            reader_sender,
            receiver_encryptor,
            udp_pool.clone(),
            local_server,
            IndexSet::new(),
            max_length,
            scancel,
        ));
        let sender_result = tokio::spawn(basic_writer_executor(
            writer_receiver,
            status_sender,
            sender_encryptor,
            udp_pool,
        ));
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
}
