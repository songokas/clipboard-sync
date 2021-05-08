// #![cfg(feature = "rustls")]

use log::{debug, error, info, warn};
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
use crate::filesystem::read_file;

fn configure_client(server_certs: &[&[u8]]) -> Result<ClientConfig, EndpointError> {
    let mut cfg_builder = ClientConfigBuilder::default();
    for cert in server_certs {
        let chain = CertificateChain::from_pem(cert)?;
        for pcert in chain {
            cfg_builder
                .add_certificate_authority(Certificate::from(pcert))
                .map_err(|e| EndpointError::InvalidKey(format!("Invalid key {}", e)))?;
        }
    }
    Ok(cfg_builder.build())
}

pub async fn configure_server(certificates: &Certificates) -> Result<ServerConfig, EndpointError> {
    let cert = read_file(&certificates.public_key, 10_000)
        .map_err(|e| EndpointError::InvalidKey(format!("cert not found {:?}", cert_path)))?;

    let chain = CertificateChain::from_pem(&cert)?;

    let priv_key_data = read_file(&certificates.private_key, 10_000)?;
    let priv_key = PrivateKey::from_pem(&priv_key_data)?;

    let mut transport_config = TransportConfig::default();
    transport_config.max_concurrent_uni_streams(0); //.unwrap();
    let mut server_config = ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut cfg_builder = ServerConfigBuilder::new(server_config);

    cfg_builder.certificate(chain, priv_key)?;
    return Ok(cfg_builder.build());
}

pub async fn make_client_endpoint(
    bind_addr: &SocketAddr,
    server_certs: &[&[u8]],
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
    let (endpoint, incoming) = endpoint_builder.bind(bind_addr)?;
    return Ok(incoming);
}

pub async fn obtain_client_endpoint(
    local_addr: &SocketAddr,
    certificates: &Certificates,
) -> Result<Endpoint, ConnectionError> {
    // let config_path = dirs::config_dir().ok_or_else(|| {
    //     ConnectionError::InvalidKey(
    //         "Quic unable to find config path with keys CONFIG_PATH is usually ~/.config".to_owned(),
    //     )
    // })?;
    
    let verify_path = certificates.verify_dir.join(format!("cert.crt"));
    
    let verify_cert = read_file(&verify_path., 10_000)?;
    let certs = [verify_cert.as_slice()];

    let endpoint: Endpoint = make_client_endpoint(local_addr, &certs).await?;
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
            mut bi_streams,
            mut uni_streams,
            ..
        } = inc.await?;

        debug!("connection {:?}", connection.remote_address(),);

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
