use rustls_tokio_stream::{TlsStreamRead, TlsStreamWrite};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::bytes::BufMut;

use crate::stream::{ReadStream, WriteStream};

impl ReadStream for TlsStreamRead {
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
        Ok(())
    }
}

impl WriteStream for TlsStreamWrite {
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryptor::NoEncryptor;
    use crate::errors::ConnectionError;
    use crate::message::SendGroup;
    use crate::pools::tls_stream_pool::TlsStreamPool;
    use crate::protocol_readers::tcp_tls::create_tcp_tls_reader;
    use crate::protocol_writers::tcp_tls::tcp_tls_writer_executor;
    use crate::{config::FileCertificates, protocol_readers::ReceiverConfig};
    use indexmap::indexmap;
    use serial_test::serial;
    use tokio::sync::mpsc::channel;
    use tokio_util::sync::CancellationToken;

    async fn send_receive(sample: serde_json::Value) {
        let group =
            SendGroup::from_addr("test1", sample["receive"]["allowed_host"].as_str().unwrap());
        let max_length = sample["receive"]["max_length"].as_u64().unwrap() as usize;

        let groups = indexmap! {group.name.clone() => group.clone()};
        let sender_encryptor = NoEncryptor::new(groups.clone());
        let receiver_encryptor = NoEncryptor::new(groups);

        let (reader_sender, reader_receiver) = channel(10);
        let (writer_sender, writer_receiver) = channel(10);
        let (status_sender, status_receiver) = channel(10);
        let cancel: CancellationToken = CancellationToken::new();
        let scancel = cancel.clone();

        let client_certs = FileCertificates {
            private_key: "tests/certs/testclient.key".parse().unwrap(),
            certificate_chain: "tests/certs/testclient.crt".parse().unwrap(),
            remote_certificates: Some("tests/certs/cert-verify/for-client".parse().unwrap()),
        };

        let server_certs = FileCertificates {
            private_key: "tests/certs/localhost.key".parse().unwrap(),
            certificate_chain: "tests/certs/localhost.crt".parse().unwrap(),
            remote_certificates: Some("tests/certs/cert-verify/for-server".parse().unwrap()),
        };

        let obtain_client_certs = move || {
            Ok(Some(
                client_certs
                    .clone()
                    .try_into()
                    .map_err(|(e, _)| ConnectionError::from(e))?,
            ))
        };

        let obtain_server_certs = move || {
            server_certs
                .clone()
                .try_into()
                .map_err(|(e, _)| ConnectionError::from(e))
        };

        let local_server: SocketAddr = sample["receive"]["bind_address"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let stream_pool = TlsStreamPool::default();
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
            create_tcp_tls_reader(
                reader_sender,
                receiver_encryptor,
                spool,
                receiver_config,
                obtain_server_certs,
                false,
            )
            .await
        });
        let sender_result = tokio::spawn(async move {
            tcp_tls_writer_executor(
                writer_receiver,
                status_sender,
                sender_encryptor,
                stream_pool,
                obtain_client_certs,
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
            // TODO investigate why it fails on windows and mac
            #[cfg(target_os = "linux")]
            include_str!("../../tests/testing_data/mbytes.json"),
        ];
        for s in samples {
            let value = serde_json::from_str(s).unwrap();
            send_receive(value).await;
        }
    }
}
