use bytes::Bytes;
use log::debug;
use tokio::time::timeout;

use core::convert::TryFrom;
use core::time::Duration;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::certificate::Certificates;
use crate::errors::ConnectionError;

pub async fn send_stream(connection: &Connection, data: Bytes) -> Result<usize, ConnectionError> {
    debug!("Send stream data_size={}", data.len());
    let mut send = connection.open_uni().await?;
    send.write_all(&data).await?;
    send.finish().map_err(|_| ConnectionError::FailedToClose)?;
    send.stopped()
        .await
        .map_err(|_| ConnectionError::FailedToClose)?;
    Ok(data.len())
}

pub async fn read_stream(
    connection: &Connection,
    max_len: usize,
    wait_for: Duration,
) -> Result<Vec<u8>, ConnectionError> {
    debug!("Receive stream remote_addr={}", connection.remote_address());
    let mut stream = match timeout(wait_for, connection.accept_uni()).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(ConnectionError::QuicConnection(e)),
        Err(_) => {
            return Err(ConnectionError::Timeout("quic stream", wait_for));
        }
    };

    debug!("Stream accepted");

    let received_data =
        stream
            .read_to_end(max_len)
            .await
            .map_err(|_| ConnectionError::LimitReached {
                received: max_len + 1,
                max_len,
            })?;

    debug!("Stream finished reading");
    Ok(received_data)
}

pub fn obtain_server_endpoint(
    local_addr: SocketAddr,
    certificates: Certificates,
    client_auth: bool,
) -> Result<Endpoint, ConnectionError> {
    let server_config = configure_server(certificates, client_auth)?;
    let endpoint = Endpoint::server(server_config, local_addr)?;
    Ok(endpoint)
}

pub fn obtain_client_endpoint(
    local_addr: SocketAddr,
    certificates: Option<Certificates>,
) -> Result<Endpoint, ConnectionError> {
    let client_config = configure_client(certificates)?;
    let mut endpoint = Endpoint::client(local_addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

pub fn configure_client(
    certificates: Option<Certificates>,
) -> Result<quinn::ClientConfig, ConnectionError> {
    let client_crypto = crate::tls::configure_client(certificates)?;
    let client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto)
            .map_err(|e| ConnectionError::BadConfiguration(e.to_string()))?,
    ));

    Ok(client_config)
}

fn configure_server(
    certificates: Certificates,
    client_auth: bool,
) -> Result<ServerConfig, ConnectionError> {
    let server_crypto = crate::tls::configure_server(certificates, client_auth)?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto)
            .map_err(|e| ConnectionError::BadConfiguration(e.to_string()))?,
    ));

    Ok(server_config)
}

#[cfg(test)]
mod tests {
    use core::convert::TryInto;

    use super::*;
    use crate::config::FileCertificates;
    use crate::encryptor::NoEncryptor;
    use crate::message::SendGroup;
    use crate::pools::connection_pool::ConnectionPool;
    use crate::protocol_readers::quic::create_quic_reader;
    use crate::protocol_writers::quic::quic_writer_executor;
    use indexmap::{indexmap, IndexSet};
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

        let local_server: SocketAddr = sample["receive"]["bind_address"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

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

        let pool = ConnectionPool::default();
        let spool = pool.clone();
        let receiver_result = tokio::spawn(async move {
            create_quic_reader(
                reader_sender,
                receiver_encryptor,
                spool,
                IndexSet::new(),
                local_server,
                max_length,
                obtain_server_certs,
                true,
                scancel,
            )
            .await
        });
        let sender_result = tokio::spawn(async move {
            quic_writer_executor(
                writer_receiver,
                status_sender,
                sender_encryptor,
                pool,
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
            include_str!("../../tests/testing_data/mbytes.json"),
        ];
        for s in samples {
            let value = serde_json::from_str(s).unwrap();
            send_receive(value).await;
        }
    }
}
