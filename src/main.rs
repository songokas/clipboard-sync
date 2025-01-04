use bytes::Bytes;
use clipboard_sync::clipboards::ClipboardHash;
use clipboard_sync::clipboards::ClipboardReadMessage;
use clipboard_sync::clipboards::ModifiedFiles;
use clipboard_sync::config_loader::load_configuration;
use clipboard_sync::defaults::{DEFAULT_CLIPBOARD, MAX_CHANNEL};
use clipboard_sync::executors::{
    receiver_executors, sender_protocol_executors, sender_reader_executors,
};

use clipboard_sync::message::{GroupName, MessageType};
use clipboard_sync::pools::PoolFactory;
use clipboard_sync::protocols::{StatusHandler, StatusInfo, StatusMessage};
use core::time::Duration;
use indexmap::IndexSet;
use log::{debug, error, info, warn};
use std::fs::create_dir_all;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc::channel;
use tokio::task::JoinSet;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use env_logger::Env;
use std::convert::TryInto;

use clap::Parser;

use clipboard_sync::certificate::{
    generate_der_certificates, random_certificate_subject, CertificateResult,
};
use clipboard_sync::config::CliConfig;
use clipboard_sync::config::{get_app_dir, load_default_certificates};
use clipboard_sync::errors::{CliError, ConnectionError};
#[cfg(feature = "ntp")]
use clipboard_sync::time::update_time_diff;

#[tokio::main]
async fn main() -> Result<(), CliError> {
    let mut cli_config = CliConfig::parse();
    let (verbosity, custom_format) = if let Some(v) = cli_config.verbosity.strip_suffix("=simple") {
        (v.to_string(), true)
    } else {
        (cli_config.verbosity.to_string(), false)
    };

    let mut builder = env_logger::Builder::from_env(Env::default().default_filter_or(verbosity));
    if custom_format {
        use std::io::Write;
        builder.format(|buf, record| writeln!(buf, "{}", record.args()));
    }
    builder.init();

    let private_key = cli_config.private_key.clone();
    let public_key = cli_config.certificate_chain.clone();
    let cert_dir = cli_config.remote_certificates.clone();

    let tls_server_no_verify = cli_config.danger_server_no_verify;
    let send_public_key = cli_config.send_public_key;
    let receive_public_key = cli_config.receive_public_key;
    let send_once = cli_config.send_once || send_public_key;
    let receive_once = cli_config.receive_once || receive_public_key;
    // receive public key to the remote certificate directory
    if receive_public_key && cli_config.clipboard == DEFAULT_CLIPBOARD {
        if let Some(remote_cert_dir) = cli_config.remote_certificates.clone().or_else(|| {
            get_app_dir(cli_config.app_dir.clone())
                .ok()
                .map(|p| p.join("cert-verify"))
        }) {
            if let Err(e) = create_dir_all(&remote_cert_dir) {
                warn!(
                    "Unable to create directory {} {e}",
                    remote_cert_dir.to_string_lossy()
                );
            } else {
                cli_config.clipboard = remote_cert_dir.to_string_lossy().to_string();
            }
        }
    }

    let (full_config, config_file_certificates) = load_configuration(cli_config)?;

    let app_dir = full_config.app_dir.clone();

    let load_server_certs = move || -> CertificateResult {
        let err = |(e, p): (_, PathBuf)| {
            ConnectionError::BadConfiguration(format!(
                "Unable to load certificates path={} {e}",
                p.to_string_lossy()
            ))
        };
        if let Some(c) = config_file_certificates.clone() {
            debug!("Loading certificates from configuration file");
            return c.try_into().map_err(err);
        }

        if let Ok(c) = load_default_certificates(
            app_dir.clone(),
            private_key.as_deref().map(Path::new),
            public_key.as_deref().map(Path::new),
            cert_dir.as_deref().map(Path::new),
        ) {
            debug!("Loading certificates from configuration directory");
            return c.try_into().map_err(err);
        }

        Ok(generate_der_certificates(random_certificate_subject()))
    };

    let server_certs = load_server_certs.clone();
    let load_client_certs = move || {
        if tls_server_no_verify {
            return Ok(None);
        }
        server_certs().map(|c| c.into())
    };

    let launch_receiver = receive_once || !send_once;
    let launch_sender = send_once || !receive_once;
    let (network_status_sender, mut network_status_receiver) = channel(MAX_CHANNEL);
    let (clipboard_status_sender, mut clipboard_status_receiver) = channel(MAX_CHANNEL);

    let mut handles = JoinSet::new();

    let clipboard_hash = ClipboardHash::default();
    let modified_files = ModifiedFiles::default();
    let pools = PoolFactory::default();
    let cancel: CancellationToken = CancellationToken::new();

    #[cfg(feature = "ntp")]
    match &full_config.ntp_server {
        Some(s) if !s.is_empty() => {
            handles.spawn(update_time_diff(s.clone(), cancel.clone()));
        }
        _ => debug!("Ntp server not provided"),
    };

    if launch_receiver {
        receiver_executors(
            &mut handles,
            clipboard_status_sender,
            &full_config,
            pools.clone(),
            clipboard_hash.clone(),
            modified_files.clone(),
            load_server_certs.clone(),
            cancel.clone(),
        );

        if receive_once {
            info!("Waiting to receive clipboard once");
            let message = clipboard_status_receiver.recv().await;
            let wait_for_copy = if let Some(StatusMessage::Ok(StatusInfo {
                message_type,
                data_size,
                destination,
                status_handler,
            })) = message
            {
                if receive_public_key || matches!(message_type, MessageType::PublicKey) {
                    info!("Received public key {data_size} in {destination}. Verify it before using it `openssl x509 -in {destination} -text -noout`");
                } else {
                    info!("Received bytes {data_size} in {destination}");
                }
                matches!(status_handler, StatusHandler::Clipboard)
                    .then_some(full_config.receive_once_wait)
            } else {
                info!("No data received");
                None
            };

            cancel.cancel();
            if let Some(wait) = wait_for_copy {
                sleep(wait).await;
            }
        }
    }

    if launch_sender {
        sleep(Duration::from_millis(500)).await;

        let protocol_client = sender_protocol_executors(
            &mut handles,
            network_status_sender,
            &full_config,
            pools,
            load_client_certs,
        );
        if !send_public_key {
            sender_reader_executors(
                &mut handles,
                protocol_client.clone(),
                &full_config,
                clipboard_hash,
                modified_files,
                cancel.clone(),
            );
        }
        // send heartbeat on startup
        let groups: IndexSet<GroupName> = full_config
            .groups
            .iter()
            .filter(|(_, g)| g.heartbeat.is_some())
            .map(|(k, _)| k.clone())
            .collect();
        if !groups.is_empty() {
            protocol_client
                .send(ClipboardReadMessage {
                    groups,
                    message_type: MessageType::Heartbeat,
                    data: Bytes::from(0_u64.to_be_bytes().to_vec()),
                })
                .await
                .expect("Unable to send initial heartbeats");
        }

        #[cfg(feature = "tls")]
        if send_public_key {
            let groups: IndexSet<GroupName> =
                full_config.groups.iter().map(|(k, _)| k.clone()).collect();
            let certificates = load_server_certs()?;
            let data: Vec<u8> = certificates
                .server_certificate_chain
                .into_iter()
                .flat_map(|c| clipboard_sync::encryption::der_to_pem(c.as_ref()))
                .collect();
            info!(
                "Sending public key {} to {groups:?}",
                clipboard_sync::encryption::hash(&data)
            );
            protocol_client
                .send(ClipboardReadMessage {
                    groups,
                    message_type: MessageType::PublicKey,
                    data: Bytes::from(data),
                })
                .await
                .expect("Unable to send public key");
        }

        if send_once {
            info!("Waiting to send clipboard once");
            match network_status_receiver.recv().await {
                Some(StatusMessage::Ok(m)) => {
                    info!("Sent bytes {}", m.data_size);
                }
                Some(StatusMessage::Err(e)) => {
                    error!("Failed with error {e}");
                }
                None => (),
            }

            cancel.cancel();
        }
    }

    let mut result = Ok(());

    while let Some(item) = handles.join_next().await {
        match item {
            Ok(Ok((name, c))) => {
                debug!("Finished {} processed messages {}", name, c);
            }
            Ok(Err(e)) => {
                error!("Finished with error: {e}");
                result = Err(e);
            }
            Err(e) => {
                debug!("Failed to join task {e}");
            }
        }
    }

    result
}
