use core::convert::TryInto;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Duration;

use bytes::Bytes;
use certificate::{
    generate_pem_certificates, get_pem_certificate_info, random_certificate_subject,
};
use clipboards::ClipboardReadMessage;
use config::{FullConfig, UserCertificates};
use defaults::MAX_CHANNEL;
use executors::sender_protocol_executors;
use filesystem::{bytes_to_dir, serialize_files};
use jni::objects::{AutoLocal, JByteArray, JClass, JMap, JObject, JString};
use jni::sys::{jboolean, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use log::warn;
#[cfg(target_os = "android")]
use log::LevelFilter;

#[cfg(target_os = "android")]
use android_logger::Config;
use pools::PoolFactory;
use protocols::{ProtocolReadMessage, StatusMessage};
use runner::StatusInfo;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::channel;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::timeout;

#[cfg(feature = "tls")]
pub mod certificate;
#[cfg(not(feature = "tls"))]
pub mod certificate {
    use crate::config::FileCertificates;
    use crate::config::UserCertificates;
    use crate::errors::ConnectionError;
    use std::path::PathBuf;
    pub type Certificates = ();
    pub type CertificateInfo = ();
    pub type CertificateResult = Result<Certificates, ConnectionError>;
    pub type OptionalCertificateResult = Result<Option<Certificates>, ConnectionError>;

    pub fn generate_pem_certificates(_: String) -> Option<UserCertificates> {
        None
    }
    pub fn generate_der_certificates(_: String) -> Certificates {
        ()
    }

    pub fn random_certificate_subject() -> String {
        "not-compiled".to_string()
    }
    pub fn get_pem_certificate_info(_cert: &str) -> Option<CertificateInfo> {
        None
    }

    impl TryFrom<FileCertificates> for Certificates {
        type Error = (ConnectionError, PathBuf);

        fn try_from(_user_certs: FileCertificates) -> Result<Self, Self::Error> {
            Err((
                ConnectionError::BadConfiguration("Tls not compiled".to_string()),
                PathBuf::new(),
            ))
        }
    }
    impl TryFrom<UserCertificates> for Certificates {
        type Error = ConnectionError;

        fn try_from(_user_certs: UserCertificates) -> Result<Self, Self::Error> {
            Err(ConnectionError::BadConfiguration(
                "Tls not compiled".to_string(),
            ))
        }
    }
}
pub mod clipboard_readers;
pub mod clipboard_writers;
pub mod clipboards;
pub mod config;
pub mod config_loader;
pub mod defaults;
pub mod encryption;
pub mod encryptor;
pub mod errors;
pub mod executors;
pub mod filesystem;
pub mod forwarders;
mod identity;
pub mod message;
mod multicast;
pub mod pools;
pub mod protocol;
mod protocol_readers;
mod protocol_writers;
pub mod protocols;
#[cfg(feature = "tls")]
pub mod tls;

#[cfg(not(target_os = "android"))]
pub mod relays;
mod runner;
pub mod socket;
mod stream;
pub mod time;
mod validation;

use crate::message::MessageType;
use crate::runner::{create_config, create_runner, Runner, Status};

static CURRENT_RUNNER: LazyLock<Mutex<Vec<Runner>>> = LazyLock::new(|| {
    #[cfg(target_os = "android")]
    android_logger::init_once(Config::default().with_max_level(LevelFilter::Debug));
    Mutex::new(Vec::new())
});

static CURRENT_RUNTIME: LazyLock<Runtime> =
    LazyLock::new(|| Runtime::new().expect("Failed to start runtime"));

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_startSync(
    mut env: JNIEnv,
    _: JClass,
    input: JString,
) -> jstring {
    let config_str: String = match env.get_string(&input) {
        Ok(b) => b.into(),
        Err(_) => return create_string(&mut env, "Could not get json config"),
    };

    let result = CURRENT_RUNTIME.block_on(start(config_str));

    let message = Status::from(result);

    let status_str = match serde_json::to_string(&message) {
        Ok(s) => s,
        Err(_) => "Unable to return response".into(),
    };

    create_string(&mut env, status_str)
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_stopSync(
    mut env: JNIEnv,
    _: JClass,
) -> jstring {
    let result = CURRENT_RUNTIME.block_on(stop());

    let message = Status::from(result);

    let status_str = match serde_json::to_string(&message) {
        Ok(s) => s,
        Err(_) => "Unable to return response".into(),
    };

    create_string(&mut env, status_str)
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_status(
    mut env: JNIEnv,
    _: JClass,
) -> jstring {
    let result = CURRENT_RUNTIME.block_on(status());

    let message = Status::from(result);

    let status_str = match serde_json::to_string(&message) {
        Ok(s) => s,
        Err(_) => "Unable to return response".into(),
    };

    create_string(&mut env, status_str)
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_generateCertificates(
    mut env: JNIEnv,
    _: JClass,
) -> jstring {
    let user_certificates = generate_pem_certificates(random_certificate_subject());
    let certs = match serde_json::to_string(&user_certificates) {
        Ok(s) => s,
        Err(_) => "Unable to return response".into(),
    };

    create_string(&mut env, certs)
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_certificateInfo(
    mut env: JNIEnv,
    _: JClass,
    input: JString,
) -> jstring {
    let cert: String = match env.get_string(&input) {
        Ok(b) => b.into(),
        Err(_) => return create_string(&mut env, "Could obtain certificate"),
    };
    let user_certificates = get_pem_certificate_info(&cert);
    let certs = match serde_json::to_string(&user_certificates) {
        Ok(s) => s,
        Err(_) => "Unable to return response".into(),
    };

    create_string(&mut env, certs)
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_receive(
    mut env: JNIEnv,
    _: JClass,
) -> jstring {
    let Some((
        ProtocolReadMessage {
            message_type,
            remote,
            data,
            ..
        },
        max_file_size,
        app_dir,
    )) = CURRENT_RUNTIME.block_on(receive())
    else {
        return create_string(&mut env, "");
    };
    match message_type {
        MessageType::Text | MessageType::PublicKey => {
            create_string(&mut env, String::from_utf8_lossy(&data))
        }
        MessageType::File | MessageType::Files | MessageType::Directory => {
            match bytes_to_dir(
                &app_dir,
                Bytes::from(data),
                &remote.to_string(),
                max_file_size,
            ) {
                Ok(files) => {
                    let clipboard = files
                        .into_iter()
                        .map(|s| format!("file://{}", s.to_string_lossy()))
                        .collect::<Vec<String>>()
                        .join("\n");
                    create_string(&mut env, clipboard)
                }
                Err(e) => {
                    warn!("Unable to write to directory {e}");
                    create_string(&mut env, format!("Unable to write to directory {e}"))
                }
            }
        }
        MessageType::Handshake | MessageType::Heartbeat => create_string(&mut env, ""),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_isRunning(
    _: JNIEnv,
    _: JClass,
) -> jboolean {
    let status = CURRENT_RUNTIME.block_on(is_started());
    if status {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_queue(
    mut env: JNIEnv,
    _: JClass,
    input: JByteArray,
    clipboard_type: JString,
) -> jstring {
    let (message_type, bytes) = match get_content_to_send(&mut env, input, clipboard_type) {
        Ok(r) => r,
        Err(s) => return s,
    };
    let result = CURRENT_RUNTIME.block_on(queue(bytes, message_type));
    match result {
        Ok(_) => create_string(&mut env, ""),
        Err(e) => create_string(&mut env, e),
    }
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_queueFiles(
    mut env: JNIEnv,
    _: JClass,
    map: JObject,
) -> jstring {
    let map = JMap::from_env(&mut env, &map).expect("Valid map");
    let bytes = match get_files_to_send(&mut env, map) {
        Ok(b) => b,
        Err(e) => return e,
    };

    let result = CURRENT_RUNTIME.block_on(queue(bytes, MessageType::Files));
    match result {
        Ok(_) => create_string(&mut env, ""),
        Err(e) => create_string(&mut env, e),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_send(
    mut env: JNIEnv,
    _: JClass,
    config_json: JString,
    input: JByteArray,
    clipboard_type: JString,
    timeout_ms: jlong,
) -> jstring {
    let config_str: String = match env.get_string(&config_json) {
        Ok(b) => b.into(),
        Err(_) => return create_string(&mut env, "Could not get json config"),
    };

    let (message_type, bytes) = match get_content_to_send(&mut env, input, clipboard_type) {
        Ok(r) => r,
        Err(s) => return s,
    };
    let result = CURRENT_RUNTIME.block_on(send(
        config_str,
        bytes,
        message_type,
        Duration::from_millis(timeout_ms as u64),
    ));
    let status_str = match result {
        Ok(b) => format!("bytes sent {}", b),
        Err(e) => e,
    };
    create_string(&mut env, status_str)
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_sendFiles(
    mut env: JNIEnv,
    _: JClass,
    config_json: JString,
    map: JObject,
    timeout_ms: jlong,
) -> jstring {
    let map = JMap::from_env(&mut env, &map).expect("Valid map");
    let config_str: String = match env.get_string(&config_json) {
        Ok(b) => b.into(),
        Err(_) => return create_string(&mut env, "Could not get json config"),
    };

    let bytes = match get_files_to_send(&mut env, map) {
        Ok(b) => b,
        Err(e) => return e,
    };

    let result = CURRENT_RUNTIME.block_on(send(
        config_str,
        bytes,
        MessageType::Files,
        Duration::from_millis(timeout_ms as u64),
    ));
    let status_str = match result {
        Ok(b) => format!("bytes sent {}", b),
        Err(e) => e,
    };
    create_string(&mut env, status_str)
}

pub async fn is_started() -> bool {
    !(*(CURRENT_RUNNER.lock().await)).is_empty()
}

pub async fn start(config_str: String) -> Result<(), String> {
    if is_started().await {
        stop().await;
    }

    match create_runner(config_str).await {
        Ok(runner) => {
            (*(CURRENT_RUNNER.lock().await)).push(runner);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

pub async fn send(
    config_str: String,
    clipboard: Bytes,
    message_type: MessageType,
    timeout: Duration,
) -> Result<usize, String> {
    let (full_config, user_certificates, danger_server_no_verify) =
        create_config(config_str)?;
    send_data(
        full_config,
        user_certificates,
        clipboard,
        message_type,
        danger_server_no_verify,
        timeout,
    )
    .await
}

pub async fn queue(data: Bytes, message_type: MessageType) -> Result<(), String> {
    let mut guard = CURRENT_RUNNER.lock().await;
    if (*guard).is_empty() {
        return Err("Unable to queue. Not running".to_string());
    }
    (*guard)[0].queue(data, message_type)
}

pub async fn status() -> Option<StatusInfo> {
    let mut guard = CURRENT_RUNNER.lock().await;
    if (*guard).is_empty() {
        return None;
    }
    Some((*guard)[0].status())
}

pub async fn receive() -> Option<(ProtocolReadMessage, usize, PathBuf)> {
    let mut guard = CURRENT_RUNNER.lock().await;
    if (*guard).is_empty() {
        return None;
    }
    (*guard)[0].receive()
}

pub async fn stop() -> bool {
    let mut guard = CURRENT_RUNNER.lock().await;

    if !guard.is_empty() {
        let runner = guard.remove(0);
        return runner.stop().await.is_ok();
    }
    false
}

fn create_string(env: &mut JNIEnv, message: impl AsRef<str>) -> jstring {
    let output = env
        .new_string(message.as_ref().to_string())
        .expect("Couldn't create java string!");
    output.into_raw()
}

fn get_content_to_send(
    env: &mut JNIEnv,
    input: JByteArray,
    file_name: JString,
) -> Result<(MessageType, Bytes), jstring> {
    let bytes = match env.convert_byte_array(input) {
        Ok(b) => b,
        Err(_) => return Err(create_string(env, "Could not convert bytes")),
    };

    let message_str: String = match env.get_string(&file_name) {
        Ok(b) => b.into(),
        Err(_) => return Err(create_string(env, "Could not get clipboard type")),
    };

    Ok(match message_str.as_ref() {
        "text" => (MessageType::Text, Bytes::from(bytes)),
        "public_key" => (MessageType::PublicKey, Bytes::from(bytes)),
        file_name => {
            let files = vec![(file_name.to_string(), bytes)];
            let bytes = serialize_files(files);
            (MessageType::Files, bytes)
        }
    })
}

fn get_files_to_send(env: &mut JNIEnv, map: JMap) -> Result<Bytes, jstring> {
    let mut files = Vec::<(String, Vec<u8>)>::new();
    let Ok(mut iterator) = map.iter(env) else {
        return Err(create_string(env, "Could not obtain files"));
    };

    while let Some((key, value)) = iterator
        .next(env)
        .map_err(|_| create_string(env, "Could not obtain files"))?
    {
        let key: AutoLocal<JObject> = env.auto_local(key);
        let value: AutoLocal<JObject> = env.auto_local(value);

        let arr: &JByteArray = value.as_ref().into();
        let bytes = match env.convert_byte_array(arr) {
            Ok(b) => b,
            Err(_) => return Err(create_string(env, "Could not convert bytes")),
        };
        let file_name: String = match env.get_string(key.as_ref().into()) {
            Ok(b) => b.into(),
            Err(_) => return Err(create_string(env, "Could not get clipboard type")),
        };
        files.push((file_name, bytes));
    }
    Ok(serialize_files(files))
}

async fn send_data(
    full_config: FullConfig,
    user_certificates: Option<UserCertificates>,
    data: Bytes,
    message_type: MessageType,
    danger_server_no_verify: bool,
    wait_for: Duration,
) -> Result<usize, String> {
    let load_certs = move || {
        if danger_server_no_verify {
            return Ok(None);
        }
        user_certificates
            .clone()
            .map(|certs| certs.try_into().map_err(Into::into))
            .transpose()
    };
    let (status_sender, mut status_receiver) = channel(MAX_CHANNEL);
    let mut handles = JoinSet::new();
    let sender = sender_protocol_executors(
        &mut handles,
        status_sender,
        &full_config,
        PoolFactory::default(),
        load_certs,
    );
    sender
        .send(ClipboardReadMessage {
            groups: full_config.get_groups_by_clipboard(clipboards::ClipboardSystem::Clipboard),
            message_type,
            data,
        })
        .await
        .map_err(|_| "Unable to send clipboard".to_string())?;
    let status = timeout(wait_for, status_receiver.recv()).await;
    match status {
        Ok(Some(StatusMessage::Ok(message))) => Ok(message.data_size),
        Ok(Some(StatusMessage::Err(e))) => Err(format!("Failed to send message: {e}")),
        Ok(None) => Err("Failed to send message".to_string()),
        Err(_) => Err("Failed to send message timeout".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use runner::StatusCount;

    use super::*;

    #[test]
    fn test_start() {
        let config = r#"{
        "key":"32323232323232323232323232323232",
        "group":"default",
        "protocol":"basic",
        "hosts":{"127.0.0.1":""},
        "send_using_address":["0.0.0.0:15331"],
        "bind_address":["0.0.0.0:15330"],
        "heartbeat":0,
        "app_dir":"/tmp",
        "max_receive_size":100,
        "max_file_size":100
        }"#;
        assert_eq!(Ok(()), CURRENT_RUNTIME.block_on(start(config.to_owned())));
        assert_eq!(
            Some(StatusInfo {
                status_count: StatusCount {
                    sent: 0,
                    received: 0,
                },
                error: None
            }),
            CURRENT_RUNTIME.block_on(status())
        );
        assert!(CURRENT_RUNTIME.block_on(stop()));
    }
}
