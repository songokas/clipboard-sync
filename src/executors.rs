use std::collections::{HashMap, HashSet};

use tokio::{sync::mpsc::Sender, task::JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{
    certificate::{CertificateResult, OptionalCertificateResult},
    clipboard_readers::{
        clipboard::create_clipboard_reader,
        filesystem::{create_filesystem_reader, create_filesystem_writer},
    },
    clipboard_writers::clipboard::create_clipboard_writer,
    clipboards::{ClipboardHash, ClipboardReadMessage, ClipboardSystem, ModifiedFiles},
    config::FullConfig,
    defaults::ExecutorResult,
    encryptor::GroupEncryptor,
    forwarders::{
        clipboard_forwarder::create_protocol_to_clipboard_forwarder,
        protocol_forwarder::create_clipboard_to_protocol_forwarder,
    },
    multicast::to_multicast_ips,
    pools::PoolFactory,
    protocol::Protocol,
    protocols::{ProtocolReadMessage, StatusMessage},
};

#[allow(clippy::too_many_arguments)]
pub fn receiver_executors(
    handles: &mut JoinSet<ExecutorResult>,
    status_sender: Sender<StatusMessage>,
    full_config: &FullConfig,
    pools: PoolFactory,
    clipboard_hash: ClipboardHash,
    modified_files: ModifiedFiles,
    load_certs: impl Fn() -> CertificateResult + Clone + Send + Sync + 'static,
    cancel: CancellationToken,
) {
    let mut supported_clipboards = HashMap::new();
    for clipboard_type in full_config
        .groups
        .iter()
        .map(|(_, g)| g.clipboard.as_str().into())
        .collect::<HashSet<_>>()
    {
        let client = match clipboard_type {
            ClipboardSystem::Filesystem => {
                let (handle, client) = create_filesystem_writer(
                    status_sender.clone(),
                    modified_files.clone(),
                    full_config.max_file_size,
                );
                handles.spawn(handle);
                client
            }
            ClipboardSystem::Clipboard => {
                let (handle, client) = create_clipboard_writer(
                    status_sender.clone(),
                    clipboard_hash.clone(),
                    full_config.app_dir.clone(),
                    full_config.max_file_size,
                );
                handles.spawn(handle);
                client
            }
        };
        supported_clipboards.insert(clipboard_type, client);
    }

    let (handle, clipboard_forwarder_client) = create_protocol_to_clipboard_forwarder(
        supported_clipboards,
        full_config.get_groups_with_clipboard(),
    );
    handles.spawn(handle);
    receiver_protocol_executors(
        handles,
        clipboard_forwarder_client,
        pools,
        cancel.clone(),
        full_config,
        load_certs,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn receiver_protocol_executors(
    handles: &mut JoinSet<ExecutorResult>,
    clipboard_forwarder_client: Sender<ProtocolReadMessage>,
    pools: PoolFactory,
    cancel: CancellationToken,
    full_config: &FullConfig,
    _load_certs: impl Fn() -> CertificateResult + Clone + Send + Sync + 'static,
) {
    for (protocol, bind_address) in full_config.get_bind_addresses() {
        let groups = full_config.get_groups_by_protocol(protocol);
        let multicast_ips = to_multicast_ips(bind_address, &groups);
        match protocol {
            Protocol::Basic => {
                handles.spawn(crate::protocol_readers::basic::create_basic_reader(
                    clipboard_forwarder_client.clone(),
                    GroupEncryptor::new(groups),
                    pools.upd.clone(),
                    bind_address,
                    multicast_ips,
                    full_config.max_receive_buffer,
                    cancel.clone(),
                ));
            }
            Protocol::Tcp => {
                handles.spawn(crate::protocol_readers::tcp::create_tcp_reader(
                    clipboard_forwarder_client.clone(),
                    GroupEncryptor::new(groups),
                    pools.tcp.clone(),
                    multicast_ips,
                    bind_address,
                    full_config.max_receive_buffer,
                    cancel.clone(),
                ));
            }
            Protocol::TcpTls => {
                #[cfg(feature = "tls")]
                handles.spawn(crate::protocol_readers::tcp_tls::create_tcp_tls_reader(
                    clipboard_forwarder_client.clone(),
                    crate::encryptor::NoEncryptor::new(groups),
                    pools.tcp_tls.clone(),
                    multicast_ips,
                    bind_address,
                    full_config.max_receive_buffer,
                    _load_certs.clone(),
                    full_config.tls_client_auth,
                    cancel.clone(),
                ));
            }
            Protocol::Quic => {
                #[cfg(feature = "tls")]
                handles.spawn(crate::protocol_readers::quic::create_quic_reader(
                    clipboard_forwarder_client.clone(),
                    crate::encryptor::NoEncryptor::new(groups),
                    pools.quic.clone(),
                    multicast_ips,
                    bind_address,
                    full_config.max_receive_buffer,
                    _load_certs.clone(),
                    full_config.tls_client_auth,
                    cancel.clone(),
                ));
            }
        };
    }
}

pub fn sender_protocol_executors(
    handles: &mut JoinSet<ExecutorResult>,
    status_sender: Sender<StatusMessage>,
    full_config: &FullConfig,
    pools: PoolFactory,
    _load_certs: impl Fn() -> OptionalCertificateResult + Clone + Send + Sync + 'static,
) -> Sender<ClipboardReadMessage> {
    let mut supported_protocols = HashMap::new();

    for protocol in full_config
        .groups
        .iter()
        .map(|(_, g)| g.protocol)
        .collect::<HashSet<_>>()
    {
        let groups = full_config.get_groups_by_protocol(protocol);

        match protocol {
            Protocol::Basic => {
                let (handle, client) = crate::protocol_writers::basic::create_basic_writer(
                    status_sender.clone(),
                    GroupEncryptor::new(groups),
                    pools.upd.clone(),
                );
                handles.spawn(handle);
                supported_protocols.insert(protocol, client);
            }

            Protocol::Tcp => {
                let (handle, client) = crate::protocol_writers::tcp::create_tcp_writer(
                    status_sender.clone(),
                    GroupEncryptor::new(groups),
                    pools.tcp.clone(),
                );
                handles.spawn(handle);
                supported_protocols.insert(protocol, client);
            }
            Protocol::TcpTls => {
                #[cfg(feature = "tls")]
                {
                    let (handle, client) = crate::protocol_writers::tcp_tls::create_tcp_tls_writer(
                        status_sender.clone(),
                        crate::encryptor::NoEncryptor::new(groups),
                        pools.tcp_tls.clone(),
                        _load_certs.clone(),
                    );
                    handles.spawn(handle);
                    supported_protocols.insert(protocol, client);
                }
            }
            Protocol::Quic => {
                #[cfg(feature = "tls")]
                {
                    let (handle, client) = crate::protocol_writers::quic::create_quic_writer(
                        status_sender.clone(),
                        crate::encryptor::NoEncryptor::new(groups),
                        pools.quic.clone(),
                        _load_certs.clone(),
                    );
                    handles.spawn(handle);
                    supported_protocols.insert(protocol, client);
                }
            }
        };
    }

    let (handle, protocol_forwarder_client) = create_clipboard_to_protocol_forwarder(
        supported_protocols,
        full_config.get_groups_with_protocol(),
    );
    handles.spawn(handle);
    protocol_forwarder_client
}

pub fn sender_reader_executors(
    handles: &mut JoinSet<ExecutorResult>,
    protocol_forwarder_client: Sender<ClipboardReadMessage>,
    full_config: &FullConfig,
    clipboard_hash: ClipboardHash,
    modified_files: ModifiedFiles,
    cancel: CancellationToken,
) {
    for clipboard_type in full_config
        .groups
        .iter()
        .map(|(_, g)| g.clipboard.as_str().into())
        .collect::<HashSet<ClipboardSystem>>()
    {
        match clipboard_type {
            ClipboardSystem::Filesystem => {
                let handle = create_filesystem_reader(
                    protocol_forwarder_client.clone(),
                    full_config.get_filesystem_paths(),
                    modified_files.clone(),
                    full_config.send_clipboard_on_startup,
                    full_config.max_file_size,
                    cancel.clone(),
                );
                handles.spawn(handle);
            }
            ClipboardSystem::Clipboard => {
                let handle = create_clipboard_reader(
                    protocol_forwarder_client.clone(),
                    full_config.get_groups_by_clipboard(ClipboardSystem::Clipboard),
                    clipboard_hash.clone(),
                    full_config.send_clipboard_on_startup,
                    full_config.max_file_size,
                    cancel.clone(),
                );
                handles.spawn(handle);
            }
        };
    }
}
