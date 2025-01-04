use indexmap::IndexSet;
use log::{debug, error, info};
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use core::net::IpAddr;
use quinn::Endpoint;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::certificate::CertificateInfo;
use crate::certificate::CertificateResult;
use crate::defaults::{ExecutorResult, WAIT_TIMEOUT};
use crate::encryptor::MessageDecryptor;
use crate::identity::IdentityVerifier;
use crate::multicast::{advertise_service, join_multicast};
use crate::pools::connection_pool::ConnectionPool;
use crate::protocol::Protocol;
use crate::protocol_readers::{process_receive_stream_result, StreamReceiveError};
use crate::protocols::quic::{obtain_server_endpoint, read_stream};
use crate::protocols::ProtocolReadMessage;

#[allow(clippy::too_many_arguments)]
pub async fn create_quic_reader<V>(
    sender: Sender<ProtocolReadMessage>,
    verifier: V,
    pool: ConnectionPool,
    multicast_ips: IndexSet<IpAddr>,
    local_addr: SocketAddr,
    max_len: usize,
    obtain_certs: impl Fn() -> CertificateResult,
    client_auth: bool,
    cancel: CancellationToken,
) -> ExecutorResult
where
    V: IdentityVerifier + MessageDecryptor,
{
    let certificates = obtain_certs()?;
    let certificate_info = certificates.certificate_info();
    let endpoint = obtain_server_endpoint(local_addr, certificates, client_auth)?;
    let bound_addr = endpoint.local_addr().expect("Bound address");
    let multicast_socket = if !multicast_ips.is_empty() {
        // can not bind on the same udp port
        let multicast_socket =
            UdpSocket::bind(SocketAddr::new(bound_addr.ip(), bound_addr.port() + 1)).await?;

        for ip in multicast_ips.into_iter().filter(|i| i.is_multicast()) {
            join_multicast(&multicast_socket, ip, bound_addr.ip())?;
        }
        multicast_socket.into()
    } else {
        None
    };
    pool.add_server_endpoint(endpoint.clone(), bound_addr).await;
    quic_reader_executor(
        sender,
        verifier,
        pool,
        endpoint,
        multicast_socket,
        certificate_info,
        max_len,
        cancel,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn quic_reader_executor<V>(
    sender: Sender<ProtocolReadMessage>,
    verifier: V,
    pool: ConnectionPool,
    endpoint: Endpoint,
    multicast_socket: Option<UdpSocket>,
    certificate_info: Option<CertificateInfo>,
    max_len: usize,
    cancel: CancellationToken,
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
