//@TODO client verification support

use futures::StreamExt;
use log::{debug, info};
use quinn::{
    Certificate, CertificateChain, ClientConfig, ClientConfigBuilder, PrivateKey, ServerConfig,
    ServerConfigBuilder,
};
use quinn::{Endpoint, Incoming};
use std::net::SocketAddr;
use std::time::Instant;
use tokio::time::{timeout, Duration};

use crate::config::Certificates;
use crate::defaults::MAX_FILE_SIZE;
use crate::errors::{ConnectionError, EndpointError};
use crate::filesystem::{dir_to_dir_structure, read_file};
use crate::socket::Destination;

// @TODO failures when using protocols
// pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29", b"hq-28", b"hq-27", b"http/0.9"];

fn configure_client(
    allowed_certs: impl IntoIterator<Item = (String, Vec<u8>)>,
) -> Result<ClientConfig, EndpointError>
{
    let mut cfg_builder = ClientConfigBuilder::default();
    // cfg_builder.protocols(ALPN_QUIC_HTTP);
    for (_, cert) in allowed_certs {
        let chain = CertificateChain::from_pem(&cert)?;
        for pcert in chain {
            cfg_builder
                .add_certificate_authority(Certificate::from(pcert))
                .map_err(|e| EndpointError::InvalidKey(format!("Invalid key {}", e)))?;
        }
    }
    Ok(cfg_builder.build())
}

pub async fn configure_server(certificates: &Certificates) -> Result<ServerConfig, EndpointError>
{
    let (cert, _) = read_file(&certificates.public_key, MAX_FILE_SIZE).map_err(|e| {
        EndpointError::InvalidKey(format!("cert not found {} {}", certificates.public_key, e))
    })?;

    let chain = CertificateChain::from_pem(&cert)?;

    let (priv_key_data, _) = read_file(&certificates.private_key, MAX_FILE_SIZE)?;
    let priv_key = PrivateKey::from_pem(&priv_key_data)?;

    // let mut transport_config = TransportConfig::default();
    // transport_config.max_concurrent_uni_streams(2).map_err(|e| EndpointError::InvalidKey(format!("Configuration error max_concurrent_uni_streams {}", e)))?;
    let server_config = ServerConfig::default();
    // server_config.transport = Arc::new(transport_config);
    let mut cfg_builder = ServerConfigBuilder::new(server_config);
    // cfg_builder.protocols(ALPN_QUIC_HTTP);

    cfg_builder.certificate(chain, priv_key)?;
    Ok(cfg_builder.build())
}

pub async fn make_client_endpoint(
    bind_addr: &SocketAddr,
    server_certs: impl IntoIterator<Item = (String, Vec<u8>)>,
) -> Result<(Endpoint, Incoming), EndpointError>
{
    let client_cfg = configure_client(server_certs)?;
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.default_client_config(client_cfg);
    let (e, s) = endpoint_builder.bind(bind_addr)?;
    Ok((e, s))
}

pub async fn obtain_server_endpoint(
    bind_addr: &SocketAddr,
    certificates: &Certificates,
) -> Result<(Endpoint, Incoming), EndpointError>
{
    let server_config = configure_server(certificates).await?;
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.listen(server_config);
    let (e, s) = endpoint_builder.bind(bind_addr)?;
    Ok((e, s))
}

pub async fn obtain_client_endpoint(
    local_addr: &SocketAddr,
    certificates: &Certificates,
) -> Result<(Endpoint, Incoming), ConnectionError>
{
    let certs = dir_to_dir_structure(
        certificates
            .verify_dir
            .as_ref()
            .expect("Please provide certificate verify directory"),
        MAX_FILE_SIZE,
    );
    Ok(make_client_endpoint(local_addr, certs).await?)
}

pub async fn send_data(
    endpoint: &Endpoint,
    data: Vec<u8>,
    destination: Destination,
) -> Result<usize, ConnectionError>
{
    let connect = endpoint.connect(destination.addr(), destination.host())?; //&remote_address.ip().to_string())?;

    let quinn::NewConnection { connection, .. } = connect.await?;

    debug!("[send] connected: addr={}", connection.remote_address());

    let mut send = connection.open_uni().await?;

    send.write_all(&data).await?;
    send.finish().await?;

    debug!("[send] finished");

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok(data.len())
}

pub async fn receive_data(
    incoming: &mut Incoming,
    max_len: usize,
    timeout_callback: impl Fn(Duration) -> bool,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let now = Instant::now();
    while !timeout_callback(now.elapsed()) {
        let inc = match timeout(Duration::from_millis(50), incoming.next()).await {
            Ok(Some(inc)) => inc,
            _ => continue,
        };

        debug!("[receive] connected: addr={}", inc.remote_address());

        let quinn::NewConnection {
            connection,
            mut uni_streams,
            ..
        } = inc.await?;

        if let Some(stream) = uni_streams.next().await {
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok((vec![], connection.remote_address()));
                }
                Err(e) => {
                    return Err(ConnectionError::QuicConnection(e));
                }
                Ok(s) => s,
            };
            let req =
                stream
                    .read_to_end(max_len)
                    .await
                    .map_err(|_| ConnectionError::LimitReached {
                        received: max_len + 1,
                        max_len,
                    })?;
            return Ok((req, connection.remote_address()));
        }
    }
    Err(ConnectionError::Timeout(
        "quic receive data".to_owned(),
        now.elapsed(),
    ))
}

#[cfg(test)]
mod quinntest
{
    use super::*;
    use crate::assert_error_type;
    use crate::encryption::random;
    use tokio::try_join;

    async fn send_receive(size: usize, max_len: usize)
    {
        let local_server: SocketAddr = "127.0.0.1:9286".parse().unwrap();
        let local_client: SocketAddr = "127.0.0.1:9287".parse().unwrap();
        let certs = Certificates {
            private_key: "tests/certs/localhost.key".to_owned(),
            public_key: "tests/certs/localhost.crt".to_owned(),
            verify_dir: Some("tests/certs/cert-verify".to_owned()),
        };

        let (_, mut incoming) = obtain_server_endpoint(&local_server, &certs).await.unwrap();
        let (endpoint, _) = obtain_client_endpoint(&local_client, &certs).await.unwrap();

        let data_sent = random(size);
        let for_sending = data_sent.clone();
        let r = tokio::spawn(async move {
            receive_data(&mut incoming, max_len, |d: Duration| {
                d > Duration::from_millis(5000)
            })
            .await
        });

        let s = tokio::spawn(async move {
            send_data(
                &endpoint,
                for_sending,
                // no support for ip
                Destination::new("localhost".to_owned(), local_server),
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
    pub async fn test_data()
    {
        send_receive(5, 100).await;
        send_receive(16 * 1024 * 10, 16 * 1024 * 10 + 1000).await;
        send_receive(10, 5).await;
    }

    #[tokio::test]
    async fn test_timeout()
    {
        let local_server: SocketAddr = "127.0.0.1:3986".parse().unwrap();
        let certs = Certificates {
            private_key: "tests/certs/localhost.key".to_owned(),
            public_key: "tests/certs/localhost.crt".to_owned(),
            verify_dir: Some("tests/certs/cert-verify".to_owned()),
        };

        let (_, mut incoming) = obtain_server_endpoint(&local_server, &certs).await.unwrap();

        let result = receive_data(&mut incoming, 10, |_: Duration| true).await;

        assert_error_type!(result, ConnectionError::Timeout(..));
    }
}
