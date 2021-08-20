// #![feature(trait_alias)]
// #![feature(type_alias_impl_trait)]

use jni::objects::{JByteBuffer, JClass, JString};
use jni::sys::{jboolean, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
#[cfg(target_os = "android")]
use log::Level;

#[cfg(target_os = "android")]
use android_logger::Config;
use lazy_static::lazy_static;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

pub mod clipboards;
pub mod config;
pub mod defaults;
pub mod destination_pool;
pub mod encryption;
pub mod errors;
pub mod filesystem;
mod fragmenter;
mod identity;
pub mod message;
mod multicast;
mod notify;
pub mod process;
pub mod protocols;
#[cfg(not(target_os = "android"))]
pub mod relays;
mod runner;
pub mod socket;
mod stream;
#[cfg(test)]
mod test;
pub mod time;
mod validation;

use crate::message::MessageType;
use crate::process::{send_clipboard_contents, SocketAddrPool};
use crate::protocols::SocketPool;
use crate::runner::{create_config, create_runner, Runner, Status, StatusCount};

lazy_static! {
    static ref CURRENT_RUNNER: Mutex<Vec<Runner>> = Mutex::new(Vec::new());
    static ref CURRENT_RUNTIME: Runtime = Runtime::new().expect("Failed to start runtime");
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_startSync(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jstring
{
    #[cfg(target_os = "android")]
    android_logger::init_once(Config::default().with_min_level(Level::Debug));

    let config_str: String = match env.get_string(input) {
        Ok(b) => b.into(),
        Err(_) => return create_string(env, "Could not get json config"),
    };

    let result = CURRENT_RUNTIME.block_on(start(config_str));

    let message = Status::from(result);

    let status_str = match serde_json::to_string(&message) {
        Ok(s) => s,
        Err(_) => "Unable to return response".into(),
    };

    create_string(env, status_str)
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_stopSync(
    env: JNIEnv,
    _: JClass,
) -> jstring
{
    let result = CURRENT_RUNTIME.block_on(stop());

    let message = if result {
        Status::off("Stopped".into())
    } else {
        Status::off("Not running".into())
    };

    let status_str = match serde_json::to_string(&message) {
        Ok(s) => s,
        Err(_) => "Unable to return response".into(),
    };

    create_string(env, status_str)
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_status(
    env: JNIEnv,
    _: JClass,
) -> jstring
{
    let status = CURRENT_RUNTIME.block_on(status());

    let message = if let Some(status_count) = status {
        Status::from(status_count)
    } else {
        Status::off("Not running".into())
    };

    let status_str = match serde_json::to_string(&message) {
        Ok(s) => s,
        Err(_) => "Unable to return response".into(),
    };

    create_string(env, status_str)
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_receive(
    env: JNIEnv,
    _: JClass,
) -> jstring
{
    let message = CURRENT_RUNTIME.block_on(receive());

    match message {
        Some((bytes, _)) => {
            let utf8_string = String::from_utf8_lossy(&bytes);
            create_string(env, utf8_string)
        }
        None => create_string(env, ""),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_isRunning(
    _: JNIEnv,
    _: JClass,
) -> jboolean
{
    let status = CURRENT_RUNTIME.block_on(is_started());
    if status {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_queue(
    env: JNIEnv,
    _: JClass,
    input: JByteBuffer,
    clipboard_type: JString,
) -> jstring
{
    let (message_type, bytes) = match get_content_to_send(env, input, clipboard_type) {
        Ok(r) => r,
        Err(s) => return s,
    };
    let result = CURRENT_RUNTIME.block_on(queue(bytes, message_type));
    let status_str = match result {
        Ok(_) => format!("Ok"),
        Err(e) => e,
    };
    create_string(env, status_str)
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_send(
    env: JNIEnv,
    _: JClass,
    config_json: JString,
    input: JByteBuffer,
    clipboard_type: JString,
) -> jstring
{
    #[cfg(target_os = "android")]
    android_logger::init_once(Config::default().with_min_level(Level::Debug));

    let config_str: String = match env.get_string(config_json) {
        Ok(b) => b.into(),
        Err(_) => return create_string(env, "Could not get json config"),
    };

    let (message_type, bytes) = match get_content_to_send(env, input, clipboard_type) {
        Ok(r) => r,
        Err(s) => return s,
    };
    let result = CURRENT_RUNTIME.block_on(send(config_str, &bytes, message_type));
    let status_str = match result {
        Ok(b) => format!("bytes sent {}", b),
        Err(e) => e,
    };
    create_string(env, status_str)
}

pub async fn is_started() -> bool
{
    !(*(CURRENT_RUNNER.lock().await)).is_empty()
}

pub async fn start(config_str: String) -> Result<String, String>
{
    if is_started().await {
        stop().await;
    }

    match create_runner(config_str).await {
        Ok((runner, message)) => {
            (*(CURRENT_RUNNER.lock().await)).push(runner);
            Ok(message)
        }
        Err(e) => Err(e),
    }
}

pub async fn send(
    config_str: String,
    clipboard: &[u8],
    message_type: MessageType,
) -> Result<usize, String>
{
    let full_config = create_config(config_str)?;
    let groups = full_config.groups;
    let pool = SocketPool::default();
    let addr_pool = SocketAddrPool::new();
    return send_clipboard_contents(&pool, &addr_pool, clipboard, &groups[0], message_type).await;
}

#[cfg(target_os = "android")]
pub async fn queue(clipboard: Vec<u8>, message_type: MessageType) -> Result<(), String>
{
    let mut guard = CURRENT_RUNNER.lock().await;
    if (*guard).len() == 0 {
        return Err(format!("Unable to queue. Not running"));
    }
    return (*guard)[0].queue(clipboard, message_type);
}

pub async fn status() -> Option<StatusCount>
{
    let mut guard = CURRENT_RUNNER.lock().await;
    if (*guard).is_empty() {
        return None;
    }
    Some((*guard)[0].status())
}

pub async fn receive() -> Option<(Vec<u8>, MessageType)>
{
    let mut guard = CURRENT_RUNNER.lock().await;
    if (*guard).is_empty() {
        return None;
    }
    (*guard)[0].receive()
}

pub async fn stop() -> bool
{
    let mut guard = CURRENT_RUNNER.lock().await;

    if !(*guard).is_empty() {
        let runner = (*guard).remove(0);
        return runner.stop().await.is_ok();
    }
    false
}

fn create_string(env: JNIEnv, message: impl AsRef<str>) -> jstring
{
    let output = env
        .new_string(message.as_ref().to_string())
        .expect("Couldn't create java string!");
    output.into_inner()
}

fn get_content_to_send(
    env: JNIEnv,
    input: JByteBuffer,
    clipboard_type: JString,
) -> Result<(MessageType, Vec<u8>), jstring>
{
    let contents = match env.get_direct_buffer_address(input) {
        Ok(b) => b,
        Err(_) => return Err(create_string(env, "Could not get buffer address")),
    };

    let message_str: String = match env.get_string(clipboard_type) {
        Ok(b) => b.into(),
        Err(_) => return Err(create_string(env, "Could not get clipboard type")),
    };
    Ok(match message_str.as_ref() {
        "text" => (MessageType::Text, contents.to_vec()),
        file_name => {
            let hash = vec![(file_name.to_string(), contents.to_vec())];
            let bytes = match bincode::serialize(&hash) {
                Ok(b) => b,
                Err(e) => {
                    return Err(create_string(
                        env,
                        format!("Failed to create file {} {}", file_name, e),
                    ))
                }
            };
            (MessageType::Files, bytes)
        }
    })
}

#[cfg(test)]
mod runnertest
{
    use super::*;

    #[test]
    fn test_start()
    {
        let config = r#"{"key":"32323232323232323232323232323232","group":"default","protocol":"basic","hosts":["127.0.0.1"],"send_using_address":["0.0.0.0:15331"],"bind_address":["0.0.0.0:15330"],"heartbeat":0,"app_dir":"/tmp"}"#;
        assert_eq!(
            Ok(String::from("Started")),
            CURRENT_RUNTIME.block_on(start(config.to_owned()))
        );
        assert_eq!(
            Some(StatusCount {
                sent: 0,
                received: 0,
            }),
            CURRENT_RUNTIME.block_on(status())
        );
        assert!(CURRENT_RUNTIME.block_on(stop()));
    }
}
