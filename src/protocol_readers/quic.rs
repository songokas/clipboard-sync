use log::{debug, error, info};
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;

use quinn::Endpoint;
use std::sync::Arc;

use crate::certificate::CertificateInfo;
use crate::certificate::CertificateResult;
use crate::defaults::{ExecutorResult, WAIT_TIMEOUT};
use crate::encryptor::MessageDecryptor;
use crate::identity::IdentityVerifier;
use crate::multicast::advertise_service;
use crate::multicast::create_multicast_socket;
use crate::pools::connection_pool::ConnectionPool;
use crate::protocol::Protocol;
use crate::protocol_readers::{process_receive_stream_result, StreamReceiveError};
use crate::protocols::quic::{obtain_server_endpoint, read_stream};
use crate::protocols::ProtocolReadMessage;

use super::ReceiverConfig;

pub async fn create_quic_reader<V>(
    sender: Sender<ProtocolReadMessage>,
    verifier: V,
    pool: ConnectionPool,
    config: ReceiverConfig,
    obtain_certs: impl Fn() -> CertificateResult,
    client_auth: bool,
) -> ExecutorResult
where
    V: IdentityVerifier + MessageDecryptor,
{
    let ReceiverConfig {
        local_addr,
        multicast_ips,
        multicast_local_addr,
        ..
    } = config.clone();
    let certificates = obtain_certs()?;
    let certificate_info = certificates.certificate_info();
    let endpoint = obtain_server_endpoint(local_addr, certificates, client_auth)?;
    let bound_addr = endpoint.local_addr().expect("Bound address");
    let multicast_socket = create_multicast_socket(multicast_local_addr, multicast_ips).await?;
    pool.add_server_endpoint(endpoint.clone(), bound_addr).await;
    quic_reader_executor(
        sender,
        verifier,
        pool,
        endpoint,
        multicast_socket,
        certificate_info,
        config,
    )
    .await
}

async fn quic_reader_executor<V>(
    sender: Sender<ProtocolReadMessage>,
    verifier: V,
    pool: ConnectionPool,
    endpoint: Endpoint,
    multicast_socket: Option<UdpSocket>,
    certificate_info: Option<CertificateInfo>,
    config: ReceiverConfig,
) -> ExecutorResult
where
    V: IdentityVerifier + MessageDecryptor,
{
    let mut handles = JoinSet::new();
    let mut success_count = 0;
    let bound_addr = endpoint.local_addr().expect("Bound address");
    let server_name = certificate_info
        .as_ref()
        .and_then(|i| i.dns_names.first().cloned());
    let ReceiverConfig {
        max_len,
        cancel,
        max_connections,
        ..
    } = config;

    info!(
        "Listening on local_addr={bound_addr} protocol={} multicast_addr={} certificate_serial={} certificate_dns={}",
        Protocol::Quic,
        multicast_socket
            .as_ref()
            .map(|l| l.local_addr().expect("Multicast local addr").to_string())
            .unwrap_or_else(|| "None".to_string()),
            certificate_info.as_ref().map(|i| i.serial.as_str()).unwrap_or("None"),
            server_name.as_deref().unwrap_or("None"),
    );

    loop {
        select! {
            _ = cancel.cancelled() => {
                debug!("Quic reader cancelled");
                break;
            }
            (connection, remote_addr) = pool.wait_for_new_read_stream(bound_addr) => {
                handles.spawn(async move {
                    debug!("New stream available remote_addr={remote_addr}");
                    let data = read_stream(&connection, max_len, WAIT_TIMEOUT).await.map_err(|error| StreamReceiveError { error, remote_addr })?;
                    Ok((connection, data, remote_addr))
                });
            }
            Err(e) = async { advertise_service(multicast_socket.as_ref().expect("Multicast socket"), Protocol::Quic, bound_addr.port(), server_name.clone()).await }, if multicast_socket.is_some() => {
                debug!("Multicast failed {e}");
            }
            new_connection = endpoint.accept() => {
                let inc = match new_connection {
                    Some(inc) => inc,
                    // endpoint closed
                    _ => {
                        debug!("Quic listner closed");
                        break;
                    }
                };
                let remote_addr = inc.remote_address();

                if !inc.remote_address_validated() {
                    inc.retry().expect("Not validated remote address");
                    continue;
                }

                let Some(_) = verifier.verify(remote_addr.into()) else {
                    debug!("Peer {remote_addr} is not allowed");
                    inc.ignore();
                    continue;
                };
                if handles.len() > max_connections {
                    info!("Connection limit={max_connections} reached. Ignoring connection");
                    inc.refuse();
                    continue;
                }

                debug!("New connection remote_addr={remote_addr}");

                match inc.await {
                    Ok(c) => {
                        pool.add(Arc::new(c), bound_addr).await;
                    }
                    Err(e) => {
                        error!("Failed to connect {e}");
                    }
                };

            },
            Some(stream_finished) = handles.join_next(), if !handles.is_empty() => {
                match process_receive_stream_result(stream_finished, &verifier, &sender).await {
                    Ok((stream, remote_addr)) => {
                        success_count += 1;
                        handles.spawn(async move {
                            let data = read_stream(&stream, max_len, WAIT_TIMEOUT).await.map_err(|error| StreamReceiveError { error, remote_addr })?;
                            Ok((stream, data, remote_addr))
                        });
                    }
                    Err(Some(_)) => (),
                    Err(None) => {
                        debug!("Reader, no clients listening");
                        break;
                    }
                }
            }
        }
    }
    Ok(("quic reader", success_count))
}
