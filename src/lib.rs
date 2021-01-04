#![allow(dead_code)]

use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
#[cfg(target_os = "android")]
use log::Level;

#[cfg(target_os = "android")]
use android_logger::Config;
use lazy_static::lazy_static;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

mod channel_clipboard;
mod config;
mod defaults;
mod empty_clipboard;
mod encryption;
mod errors;
mod filesystem;
mod message;
mod process;
mod protocols;
mod runner;
mod socket;
mod test;

use crate::process::send_clipboard;
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

    let config: String = env
        .get_string(input)
        .expect("Couldn't get java string!")
        .into();

    let result = CURRENT_RUNTIME.block_on(start(config));

    let message = Status::from(result);

    let status_str = match serde_json::to_string(&message) {
        Ok(s) => s,
        Err(_) => format!("Unable to return response"),
    };

    let output = env
        .new_string(status_str)
        .expect("Couldn't create java string!");
    return output.into_inner();
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_stopSync(
    env: JNIEnv,
    _: JClass,
) -> jstring
{
    let result = CURRENT_RUNTIME.block_on(stop());

    let message = if result {
        Status::off(format!("Stopped"))
    } else {
        Status::off(format!("Not running"))
    };

    let status_str = match serde_json::to_string(&message) {
        Ok(s) => s,
        Err(_) => format!("Unable to return response"),
    };

    let output = env
        .new_string(status_str)
        .expect("Couldn't create java string!");

    return output.into_inner();
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_status(
    env: JNIEnv,
    _: JClass,
) -> jstring
{
    let status = CURRENT_RUNTIME.block_on(status());

    let message = if let Some(status_count) = status {
        Status::on(
            format!(
                "received: {} sent: {}",
                status_count.received, status_count.sent
            ),
            status_count.clipboard,
        )
    } else {
        Status::off(format!("Not running"))
    };

    let status_str = match serde_json::to_string(&message) {
        Ok(s) => s,
        Err(_) => format!("Unable to return response"),
    };

    let output = env
        .new_string(status_str)
        .expect("Couldn't create java string!");
    output.into_inner()
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_queue(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jstring
{
    let contents: String = env
        .get_string(input)
        .expect("Couldn't get java string!")
        .into();
    let result = CURRENT_RUNTIME.block_on(queue(contents));
    let status_str = match result {
        Ok(_) => format!("Ok"),
        Err(e) => e,
    };
    let output = env
        .new_string(status_str)
        .expect("Couldn't create java string!");
    output.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_clipboard_sync_ClipboardSync_send(
    env: JNIEnv,
    _: JClass,
    config_json: JString,
    input: JString,
) -> jstring
{
    let config_str: String = env
        .get_string(config_json)
        .expect("Couldn't get java string!")
        .into();
    let contents: String = env
        .get_string(input)
        .expect("Couldn't get java string!")
        .into();
    let result = CURRENT_RUNTIME.block_on(send(config_str, contents));
    let status_str = match result {
        Ok(b) => format!("bytes sent {}", b),
        Err(e) => e,
    };
    let output = env
        .new_string(status_str)
        .expect("Couldn't create java string!");
    output.into_inner()
}

pub async fn start(config_str: String) -> Result<String, String>
{
    if (*(CURRENT_RUNNER.lock().await)).len() > 0 {
        stop().await;
    }

    match create_runner(config_str).await {
        Ok((runner, message)) => {
            (*(CURRENT_RUNNER.lock().await)).push(runner);
            return Ok(message);
        }
        Err(e) => return Err(e),
    };
}

pub async fn send(config_str: String, clipboard: String) -> Result<usize, String>
{
    let full_config = create_config(config_str)?;
    let groups = full_config.groups;
    return send_clipboard(clipboard, &groups[0]).await;
}

#[cfg(target_os = "android")]
pub async fn queue(clipboard: String) -> Result<(), String>
{
    let mut guard = CURRENT_RUNNER.lock().await;
    if (*guard).len() == 0 {
        return Err(format!("Unable to queue. Not running"));
    }
    return (*guard)[0].queue(clipboard);
}

pub async fn status() -> Option<StatusCount>
{
    let mut guard = CURRENT_RUNNER.lock().await;
    if (*guard).len() == 0 {
        return None;
    }
    return Some((*guard)[0].status());
}

pub async fn stop() -> bool
{
    let mut guard = CURRENT_RUNNER.lock().await;

    if (*guard).len() > 0 {
        let runner = (*guard).remove(0);
        // std::mem::drop(guard);
        runner.stop().await.unwrap();
        return true;
    }
    return false;
}

#[cfg(test)]
mod runnertest
{
    use super::*;

    #[test]
    fn test_start()
    {
        let config = r#"{"key":"32323232323232323232323232323232","group":"","protocol":"basic","hosts":["127.0.0.1"]}"#;
        assert_eq!(
            Ok(String::from("Started")),
            CURRENT_RUNTIME.block_on(start(config.to_owned()))
        );
        assert_eq!(
            Some(StatusCount {
                sent: 0,
                received: 0,
                clipboard: String::from("")
            }),
            CURRENT_RUNTIME.block_on(status())
        );
        assert!(CURRENT_RUNTIME.block_on(stop()));
    }
}
