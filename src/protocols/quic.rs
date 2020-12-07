use quinn::{
    Certificate, CertificateChain, ClientConfig, ClientConfigBuilder, Endpoint, Incoming,
    PrivateKey, ServerConfig, ServerConfigBuilder, TransportConfig, EndpointError, ParseError
};

fn configure_client(server_certs: &[&[u8]]) -> Result<ClientConfig, ParseError> {
    let mut cfg_builder = ClientConfigBuilder::default();
    for cert in server_certs {
        cfg_builder.add_certificate_authority(Certificate::from_der(&cert)?)?;
    }
    Ok(cfg_builder.build())
}

/// Returns default server configuration along with its certificate.
fn configure_server() -> Result<(ServerConfig, Vec<u8>), ParseError> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = PrivateKey::from_pem(&priv_key)?;

    let mut transport_config = TransportConfig::default();
    transport_config.stream_window_uni(0).unwrap();
    let mut server_config = ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut cfg_builder = ServerConfigBuilder::new(server_config);
    let cert = Certificate::from_der(&cert_der)?;
    cfg_builder.certificate(CertificateChain::from_certs(vec![cert]), priv_key)?;
    Ok((cfg_builder.build(), cert_der))
}

pub fn make_client_endpoint(
    bind_addr: SocketAddr,
    server_certs: &[&[u8]],
) -> Result<Endpoint, EndpointError> {
    let client_cfg = configure_client(server_certs)?;
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.default_client_config(client_cfg);
    let (endpoint, _incoming) = endpoint_builder.bind(&bind_addr)?;
    Ok(endpoint)
}

pub fn obtain_server_endpoint(bind_addr: SocketAddr, key: &str) -> Result<Incoming, EndpointError> {
    let (server_config, server_cert) = configure_server()?;
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.listen(server_config);
    let (_endpoint, incoming) = endpoint_builder.bind(&bind_addr)?;
    return Ok(incoming);
}

pub fn obtain_client_endpoint(local_addr: &SocketAddr) -> Result<SocketEndpoint, ConnectionError>
{
    // let local_addr = socket.local_addr();
    // std::mem::drop(socket);

    let config_path = dirs::config_dir()
        .ok_or_else(|| ConnectionError::InvalidKey("Quic unable to find config path with keys CONFIG_PATH is usually ~/.config".to_owned()))?;
    let verify_path = config_path
        .join(format!("clipboard-sync/cert.crt"));

    let certs = vec![
        read_file(&verify_path.to_string_lossy(), 10_000)?,
    ];

    let endpoint = make_client_endpoint(
        local_addr,
        &certs,
    )?; 
    return Ok(SocketEndpoint::QuickClient(endpoint));
}

pub async fn send_data_quic(endpoint: &Endpoint, mut data: Vec<u8>, remote_addr: &SocketAddr, group: &Group)
    -> Result<usize, ConnectionError>
{
    let connect = endpoint.connect(&remote_addr, remote_addr.ip().to_string()).unwrap();
    let quinn::NewConnection { connection, .. } = connect.await.unwrap();
    println!("[client] connected: addr={}", connection.remote_address());

}

#[cfg(feature = "quic")]
pub async fn receive_data_quic(
    socket: &Incoming,
    max_len: usize,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    let quinn::NewConnection { connection, .. } = incoming.next().await.unwrap().await.unwrap();
    println!(
        "[server] incoming connection: addr={}",
        connection.remote_address()
    );
}