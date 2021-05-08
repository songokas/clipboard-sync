use log::{debug, info};
use quinn::{
    Certificate, CertificateChain, ClientConfig, ClientConfigBuilder, PrivateKey, ServerConfig,
    ServerConfigBuilder, TransportConfig,
};
use quinn::{Endpoint, Incoming};
use std::net::SocketAddr;
use std::sync::Arc;
// use tokio::stream::StreamExt;
use futures::StreamExt;

use crate::config::Certificates;
use crate::errors::{ConnectionError, EndpointError};
use crate::filesystem::{dir_to_dir_structure, read_file};
use crate::defaults::MAX_FILE_SIZE;

fn configure_client(allowed_certs: impl IntoIterator<Item = (String, Vec<u8>)>) -> Result<ClientConfig, EndpointError> {
    let mut cfg_builder = ClientConfigBuilder::default();
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

pub async fn configure_server(certificates: &Certificates) -> Result<ServerConfig, EndpointError> {
    let cert = read_file(&certificates.public_key, MAX_FILE_SIZE)
        .map_err(|e| EndpointError::InvalidKey(format!("cert not found {} {}", certificates.public_key, e)))?;

    let chain = CertificateChain::from_pem(&cert)?;

    let priv_key_data = read_file(&certificates.private_key, MAX_FILE_SIZE)?;
    let priv_key = PrivateKey::from_pem(&priv_key_data)?;

    let mut transport_config = TransportConfig::default();
    transport_config.max_concurrent_uni_streams(0).map_err(|e| EndpointError::InvalidKey(format!("Configuration error max_concurrent_uni_streams {}", e)))?;
    let mut server_config = ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut cfg_builder = ServerConfigBuilder::new(server_config);

    cfg_builder.certificate(chain, priv_key)?;
    return Ok(cfg_builder.build());
}

pub async fn make_client_endpoint(
    bind_addr: &SocketAddr,
    server_certs: impl IntoIterator<Item = (String, Vec<u8>)>,
) -> Result<Endpoint, EndpointError> {
    let client_cfg = configure_client(server_certs)?;
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.default_client_config(client_cfg);
    let (endpoint, _incoming) = endpoint_builder.bind(bind_addr)?;
    Ok(endpoint)
}

pub async fn obtain_server_endpoint(
    bind_addr: &SocketAddr,
    certificates: &Certificates,
) -> Result<Incoming, EndpointError> {
    let server_config = configure_server(certificates).await?;
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.listen(server_config);
    let (_, incoming) = endpoint_builder.bind(bind_addr)?;
    return Ok(incoming);
}

pub async fn obtain_client_endpoint(
    local_addr: &SocketAddr,
    certificates: &Certificates,
) -> Result<Endpoint, ConnectionError> {
    let certs = dir_to_dir_structure(&certificates.verify_dir.as_ref().expect("Certificates verify dir expected"), MAX_FILE_SIZE);
    let endpoint: Endpoint = make_client_endpoint(local_addr, certs).await?;
    return Ok(endpoint);
}

pub async fn send_data(
    endpoint: Endpoint,
    data: Vec<u8>,
    remote_address: &SocketAddr,
) -> Result<usize, ConnectionError> {
    let connect = endpoint.connect(&remote_address, &remote_address.ip().to_string())?;

    let quinn::NewConnection { connection, .. } = connect.await?;
    debug!("[client] connected: addr={}", connection.remote_address());

    let mut send = connection.open_uni().await?;

    send.write_all(&data).await?;
    send.finish().await?;

    connection.close(0u32.into(), b"done");
    return Ok(1);
}

pub async fn receive_data(
    incoming: &mut Incoming,
    max_len: usize,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError> {
    while let Some(inc) = incoming.next().await {
        debug!("[client] connected: addr={}", inc.remote_address());

        let quinn::NewConnection {
            connection,
            mut uni_streams,
            ..
        } = inc.await?;

        debug!("connection {:?}", connection.remote_address());

        while let Some(stream) = uni_streams.next().await {
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
            let req = stream.read_to_end(max_len).await?;
            return Ok((req.into(), connection.remote_address()));
        }
    }
    return Err(ConnectionError::InvalidBuffer(format!(
        "Failed to receive data"
    )));
}
