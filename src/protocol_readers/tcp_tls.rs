use log::{debug, error, info};
use rustls::ServerConfig;
use rustls_tokio_stream::TlsStream;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::select;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;

use crate::certificate::CertificateInfo;
use crate::certificate::CertificateResult;
use crate::defaults::ExecutorResult;
use crate::encryptor::MessageDecryptor;
use crate::identity::IdentityVerifier;
use crate::multicast::{advertise_service, create_multicast_socket};
use crate::pools::tls_stream_pool::TlsStreamPool;
use crate::protocol::Protocol;
use crate::protocol_readers::tcp::wait_for_stream;
use crate::protocol_readers::{process_receive_stream_result, StreamReceiveError};
use crate::protocols::tcp::obtain_server_socket;

use crate::protocols::ProtocolReadMessage;
use crate::tls::configure_server;

use super::ReceiverConfig;

pub async fn create_tcp_tls_reader<T>(
    sender: Sender<ProtocolReadMessage>,
    verifier: T,
    tls_stream_pool: TlsStreamPool,
    config: ReceiverConfig,
    obtain_certs: impl Fn() -> CertificateResult,
    client_auth: bool,
) -> ExecutorResult
where
    T: MessageDecryptor + IdentityVerifier,
{
    let ReceiverConfig {
        local_addr,
        multicast_ips,
        multicast_local_addr,
        ..
    } = config.clone();
    let certificates = obtain_certs()?;
    let certificate_info = certificates.certificate_info();
    let server_config = configure_server(certificates, client_auth)?;
    let listener = obtain_server_socket(local_addr)?;

    let multicast_socket = create_multicast_socket(multicast_local_addr, multicast_ips).await?;
    tls_reader_executor(
        sender,
        verifier,
        tls_stream_pool,
        listener,
        multicast_socket,
        certificate_info,
        server_config,
        config,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn tls_reader_executor<T>(
    sender: Sender<ProtocolReadMessage>,
    verifier: T,
    tcp_stream_pool: TlsStreamPool,
    listener: TcpListener,
    multicast_socket: Option<UdpSocket>,
    certificate_info: Option<CertificateInfo>,
    server_config: ServerConfig,
    config: ReceiverConfig,
) -> ExecutorResult
where
    T: IdentityVerifier + MessageDecryptor,
{
    let mut handles: JoinSet<Result<_, StreamReceiveError>> = JoinSet::new();
    let mut success_count = 0;

    let server_config = Arc::new(server_config);
    let bound_addr = listener.local_addr().expect("Bound address");
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
        Protocol::TcpTls,
        multicast_socket
            .as_ref()
            .map(|l| l.local_addr().expect("Multicast local addr").to_string())
            .unwrap_or_else(|| "None".to_string()),
        certificate_info
            .as_ref()
            .map(|i| i.serial.as_str())
            .unwrap_or("None"),
        server_name.as_deref().unwrap_or("None"),
    );

    loop {
        select! {
            _ = cancel.cancelled() => {
                debug!("Cancel reader");
                break;
            }
            (stream, remote_addr) = tcp_stream_pool.wait_for_new_read_stream(bound_addr) => {
                handles.spawn(wait_for_stream(stream, remote_addr, max_len));
            }
            Err(e) = async { advertise_service(multicast_socket.as_ref().expect("Multicast socket"), Protocol::TcpTls, bound_addr.port(), server_name.clone()).await }, if multicast_socket.is_some() => {
                debug!("Multicast failed {e}");
            }
            // new connection
            new_connection = listener.accept() => {
                match new_connection {
                    Ok((stream, peer_addr)) => {
                        let Some(_) = verifier.verify(peer_addr.into()) else {
                            debug!("Peer {peer_addr} is not allowed");
                            continue;
                        };

                        if handles.len() > max_connections {
                            info!("Connection limit={max_connections} reached. Ignoring connection");
                            continue;
                        }

                        debug!("New connection remote_addr={peer_addr}");

                        let mut stream = TlsStream::new_server_side(stream, server_config.clone(), None);
                        if let Err(e) = stream.handshake().await {
                            error!("Unable to complete handshake remote_addr={peer_addr} {e}");
                            continue;
                        }
                        let (reader, writer) = stream.into_split();
                        if let Err(e) = tcp_stream_pool.add_writer(bound_addr, writer).await {
                            error!("Unable to add stream: {e}");
                            continue;
                        }

                        if let Err(e) = tcp_stream_pool.add_reader(bound_addr, reader).await {
                            error!("Unable to add stream: {e}");
                            continue;
                        }
                    },
                    Err(e) => {
                        error!("Tcp accept error {e}");
                    }
                }
            }
            Some(stream_finished) = handles.join_next(), if !handles.is_empty() => {
                match process_receive_stream_result(stream_finished, &verifier, &sender).await {
                    Ok((stream, remote_addr)) => {
                        success_count += 1;
                        handles.spawn(wait_for_stream(stream, remote_addr, max_len));
                    }
                    Err(Some(remote_addr)) => {
                        tcp_stream_pool.remove(bound_addr, remote_addr).await;
                    }
                    Err(None) => {
                        debug!("Reader, no clients listening");
                        break;
                    }
                }
            }
        }
    }
    Ok(("tcptls reader", success_count))
}
