use flume::{Receiver, Sender};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio::time::{sleep, Duration};

use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;

use crate::clipboards::{
    create_targets_for_cut_files, create_text_targets, Clipboard, ClipboardType,
};
use crate::config::FullConfig;
use crate::defaults::*;
use crate::encryption::*;
use crate::errors::*;
use crate::filesystem::*;
use crate::fragmenter::{GroupsEncryptor, IdentityEncryptor};
use crate::identity::{retrieve_identity, Identity};
use crate::message::*;
use crate::protocols::*;
use crate::socket::*;

pub async fn receive_clipboard(
    mut clipboard: Clipboard,
    channel: Arc<Sender<(String, String)>>,
    local_address: SocketAddr,
    running: Arc<AtomicBool>,
    config: FullConfig,
    protocol: Protocol,
    status_channel: Arc<Sender<(u64, u64)>>,
    receive_once: bool,
) -> Result<u64, CliError>
{
    let mut local_socket = obtain_server_socket(&local_address, &protocol).await?;
    let interface_ip = local_socket.ip();
    let mut multicast = Multicast::new();
    let mut count = 0;
    let groups = config.groups;
    let encryptor = GroupsEncryptor::new(groups.clone());

    info!("Listen on {}", local_address);

    if let Some(local_addr) = interface_ip {
        if let Some(sock) = local_socket.socket() {
            multicast.join_groups(sock, &groups, &local_addr).await;
        }
    }

    let timeout = |_: Duration| !running.load(Ordering::Relaxed);

    while running.load(Ordering::Relaxed) {
        let (buf, addr) = match receive_data(
            &mut local_socket,
            &encryptor,
            &protocol,
            config.max_receive_buffer,
            timeout,
        )
        .await
        {
            Ok(v) => v,
            Err(ConnectionError::InvalidKey(e)) | Err(ConnectionError::InvalidProtocol(e)) => {
                error!("Unable to continue. {}", e);
                running.store(false, Ordering::Relaxed);
                break;
            }
            Err(ConnectionError::IoError(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => {
                error!("Error: {:?}", e);
                continue;
            }
        };

        count += 1;

        let len = buf.len();

        debug!("Packet received from {} length {}", addr, len);

        let result = handle_receive(
            &mut clipboard,
            &buf[..len],
            &Identity::from_addr(&addr),
            &groups,
        );

        match result {
            Ok((hash, group_name)) => {
                if hash.is_empty() {
                    continue;
                }
                if let Err(msg) = channel.try_send((group_name, hash)) {
                    warn!("Unable to update current hash {}", msg);
                }
            }

            Err(err) => error!("{:?}", err),
        };
        if let Err(_) = status_channel.try_send((0, count)) {
            // debug!("Unable to send status count {}", e);
        }

        if receive_once {
            running.store(false, Ordering::Relaxed);
            info!("Waiting for {} seconds", config.receive_once_wait);
            sleep(Duration::from_secs(config.receive_once_wait)).await;
            break;
        }
    }
    return Ok(count);
}

pub async fn send_clipboard(
    mut clipboard: Clipboard,
    channel: Receiver<(String, String)>,
    running: Arc<AtomicBool>,
    config: FullConfig,
    status_channel: Arc<Sender<(u64, u64)>>,
    send_once: bool,
) -> Result<u64, CliError>
{
    let mut hash_cache: HashMap<String, String> = HashMap::new();
    let mut heartbeat_cache: HashMap<String, Instant> = HashMap::new();
    let mut count = 0;
    let groups = config.groups;

    info!("Listen for clipboard changes");

    let timeout = |_: Duration| !running.load(Ordering::Relaxed);

    while running.load(Ordering::Relaxed) {
        while let Ok((group_name, rhash)) = channel.try_recv() {
            let current_hash = match hash_cache.get(&group_name) {
                Some(val) => val.clone(),
                None => "".to_owned(),
            };
            if &current_hash != &rhash {
                hash_cache.insert(group_name.clone(), rhash.clone());
                debug!(
                    "Updated current hash {} to {} for group {}",
                    current_hash, rhash, group_name
                );
            }
        }

        for group in &groups {
            let (hash, message_type, bytes) = match clipboard_group_to_bytes(
                &mut clipboard,
                group,
                hash_cache.get(&group.name),
            ) {
                Some((hash, message_type, bytes)) if bytes.len() > 0 => (hash, message_type, bytes),
                _ => {
                    if group.heartbeat > 0 {
                        send_heartbeat(&group, &mut heartbeat_cache, timeout).await;
                    }

                    continue;
                }
            };

            let entry_value = match hash_cache.get(&group.name) {
                Some(val) => val.to_owned(),
                None => {
                    if config.send_clipboard_on_startup {
                        String::from("")
                    } else {
                        hash_cache.insert(group.name.clone(), hash.clone());
                        hash.clone()
                    }
                }
            };

            if &entry_value == &hash {
                continue;
            }

            hash_cache.insert(group.name.clone(), hash.clone());

            debug!("Clipboard changed from {} to {}", entry_value, &hash);

            let data = match compress(&bytes) {
                Ok(d) => d,
                Err(err) => {
                    error!("Failed to compress data for {} {}", &group.name, err);
                    continue;
                }
            };

            count += 1;

            match send_clipboard_to_group(&data, &message_type, &group, timeout).await {
                Ok(sent) => debug!("Sent bytes {}", sent),
                Err(err) => error!("{:?}", err),
            };

            if let Err(_) = status_channel.try_send((count, 0)) {
                // debug!("Unable to send status count {}", e);
            }
        }
        if send_once {
            running.store(false, Ordering::Relaxed);
            break;
        }

        //@TODO think about the events
        let mut wait_count = 20;
        while wait_count > 0 {
            sleep(Duration::from_millis(50)).await;
            if !running.load(Ordering::Relaxed) {
                return Ok(count);
            }
            wait_count -= 1;
        }
    }
    return Ok(count);
}

pub async fn send_clipboard_contents(contents: String, group: &Group) -> Result<usize, String>
{
    let message_type = MessageType::Text;
    let bytes = contents.as_bytes();
    let data = match compress(&bytes) {
        Ok(d) => d,
        Err(err) => {
            return Err(format!(
                "Failed to compress data for {} {}",
                &group.name, err
            ));
        }
    };

    let timeout = |d: Duration| d > Duration::from_millis(DATA_TIMEOUT);

    let sent = match send_clipboard_to_group(&data, &message_type, &group, timeout).await {
        Ok(sent) => {
            debug!("Sent bytes {}", sent);
            sent
        }
        Err(err) => {
            error!("{:?}", err);
            return Err(format!("{:?}", err));
        }
    };
    return Ok(sent);
}

async fn send_heartbeat(
    group: &Group,
    heartbeat_cache: &mut HashMap<String, Instant>,
    timeout: impl Timeout,
)
{
    heartbeat_cache
        .entry(group.name.clone())
        .or_insert(Instant::now());

    let last = heartbeat_cache[&group.name];
    if last.elapsed().as_secs() > group.heartbeat {
        let data = vec![1];
        heartbeat_cache.insert(group.name.clone(), Instant::now());
        match send_clipboard_to_group(&data, &MessageType::Heartbeat, &group, timeout).await {
            Ok(sent) => debug!("Sent heartbeat bytes {}", sent),
            Err(err) => error!("{:?}", err),
        };
    }
}

fn clipboard_group_to_bytes(
    clipboard: &mut Clipboard,
    group: &Group,
    existing_hash: Option<&String>,
) -> Option<(String, MessageType, Vec<u8>)>
{
    if group.clipboard == CLIPBOARD_NAME {
        let files = clipboard.get_target_contents(ClipboardType::Files);
        match files {
            Ok(data) if data.len() > 0 => {
                let hash = hash(&data);
                if let Some(h) = existing_hash {
                    if h == &hash {
                        return None;
                    }
                }
                let clipboard_contents = String::from_utf8(data).ok()?;
                // debug!("Send file clipboard {}", clipboard_contents);
                let files: Vec<&str> = clipboard_contents.lines().collect();
                return Some((hash, MessageType::Files, files_to_bytes(files).ok()?));
            }
            _ => {
                match clipboard.get_target_contents(ClipboardType::Text) {
                    Ok(contents) => return Some((hash(&contents), MessageType::Text, contents)),
                    _ => {
                        warn!("Failed to retrieve contents");
                        return None;
                    }
                };
            }
        }
    } else if group.clipboard.ends_with("/") {
        //@TODO do not read directory every time
        match dir_to_bytes(&group.clipboard) {
            Ok(bytes) => return Some((hash(&bytes), MessageType::Directory, bytes)),
            Err(_) => return None,
        };
    } else {
        //@TODO do not read file every time
        match read_file(&group.clipboard, MAX_FILE_SIZE) {
            Ok(bytes) => return Some((hash(&bytes), MessageType::File, bytes)),
            Err(_) => return None,
        };
    }
}

fn handle_receive(
    clipboard: &mut Clipboard,
    buffer: &[u8],
    identity: &Identity,
    groups: &[Group],
) -> Result<(String, String), ClipboardError>
{
    let (message, group) = validate(buffer, groups)?;
    let bytes = decrypt(&message, identity, &group)?;
    let data = uncompress(bytes)?;
    return write_to(clipboard, &group, data, &message.message_type, identity);
}

fn write_to(
    clipboard: &mut Clipboard,
    group: &Group,
    data: Vec<u8>,
    message_type: &MessageType,
    identity: &Identity,
) -> Result<(String, String), ClipboardError>
{
    if message_type == &MessageType::Heartbeat {
        return Ok(("".to_owned(), group.name.clone()));
    }
    if group.clipboard == CLIPBOARD_NAME {
        match message_type {
            MessageType::Files => {
                let config_path = dirs::config_dir()
                    .map(|p| p.join(PACKAGE_NAME))
                    .map(|p| p.join("data"))
                    .map(|p| p.join(identity.to_string()))
                    .map(|path| path.to_string_lossy().to_string())
                    .ok_or_else(|| {
                        ClipboardError::Invalid("Unable to retrieve configuration path".to_owned())
                    })?;
                let files_created = bytes_to_dir(&config_path, data, &identity.to_string())?;
                let (clipboard_list, main_content) = create_targets_for_cut_files(files_created);
                let clipboards: HashMap<ClipboardType, &[u8]> = clipboard_list
                    .iter()
                    .map(|(k, v)| (k.clone(), v.as_bytes()))
                    .collect();
                let hash = hash(main_content.as_bytes());
                clipboard
                    .set_multiple_targets(clipboards)
                    .map_err(|err| ClipboardError::Access((*err).to_string()))?;
                return Ok((hash, group.name.clone()));
            }
            _ => {
                let hash = hash(&data);
                clipboard
                    .set_multiple_targets(create_text_targets(&data))
                    .map_err(|err| ClipboardError::Access((*err).to_string()))?;
                return Ok((hash, group.name.clone()));
            }
        };
    } else if group.clipboard.ends_with("/") {
        let hash = hash(&data);
        bytes_to_dir(&group.clipboard, data, &identity.to_string())?;
        return Ok((hash, group.name.clone()));
    }
    let hash = hash(&data);
    fs::write(&group.clipboard, data)?;
    return Ok((hash, group.name.clone()));
}

async fn send_clipboard_to_group(
    buffer: &[u8],
    message_type: &MessageType,
    group: &Group,
    //@TODO use _timeout_callback
    _timeout_callback: impl Timeout,
) -> Result<usize, ClipboardError>
{
    let mut sent = 0;
    let callback = |d: Duration| d > Duration::from_millis(2000);

    for remote_host in &group.allowed_hosts {
        let addr = match to_socket(remote_host).await {
            Ok(a) => a,
            Err(e) => {
                warn!("{:?}", e);
                continue;
            }
        };

        if addr.port() == 0 {
            debug!("Not sending to host {}", remote_host);
            continue;
        }
        let remote_ip = addr.ip();
        let local_socket =
            obtain_client_socket(&group.send_using_address, &addr, &group.protocol).await?;

        let identity = retrieve_identity(&remote_ip, local_socket.ip(), group).await?;
        let bytes = encrypt_to_bytes(&buffer, &identity, group, message_type)?;

        debug!(
            "Sending to {}:{} using {}",
            remote_ip,
            addr.port(),
            identity
        );

        let encryptor = IdentityEncryptor::new(group.clone(), identity);

        sent += send_data(
            local_socket,
            encryptor,
            &group.protocol,
            addr,
            bytes,
            callback,
        )
        .await?;
    }
    return Ok(sent);
}

#[cfg(test)]
mod processtest
{
    use super::*;
    use crate::message::Group;
    use crate::wait;
    use tokio::task::JoinHandle;
    use tokio::try_join;

    #[test]
    fn test_handle_clipboard_change()
    {
        let timeout = |d: Duration| d > Duration::from_millis(2000);
        let result = wait!(send_clipboard_to_group(
            b"test",
            &MessageType::Text,
            &Group::from_name("me"),
            timeout,
        ));
        assert_eq!(result.unwrap(), 0);

        let result = wait!(send_clipboard_to_group(
            b"test",
            &MessageType::Text,
            &Group::from_addr("me", "127.0.0.1:8801", "127.0.0.1:8093"),
            timeout,
        ));
        assert_eq!(result.unwrap(), 62);

        let result = wait!(send_clipboard_to_group(
            b"test",
            &MessageType::Text,
            &Group::from_addr("me", "127.0.0.1:8801", "127.0.0.1:0"),
            timeout,
        ));
        assert_eq!(result.unwrap(), 0);

        // let result = wait!(send_clipboard_to_group(
        //     b"test",
        //     &MessageType::Text,
        //     &Group::from_addr("me", "0.0.0.0:8801", "1.1.1.1:8093"),
        //     timeout,
        // ));
        // assert_error_type!(
        //     result,
        //     ClipboardError::ConnectionError(ConnectionError::NoPublic(_))
        // );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_wait_on_clipboard()
    {
        // env_logger::from_env(env_logger::Env::default().default_filter_or("debug")).init();
        let clipboards = Clipboard::new().unwrap();
        let clipboardr = Clipboard::new().unwrap();
        let mut group = Group::from_addr("test1", "127.0.0.1:8391", "127.0.0.1:8392");
        group.clipboard = "/tmp/twtest1".to_owned();
        let (tx, rx) = flume::bounded(MAX_CHANNEL);
        let atx = Arc::new(tx);
        let (stat_sender, _) = flume::bounded(MAX_CHANNEL);
        let sender = Arc::new(stat_sender);
        let running = Arc::new(AtomicBool::new(true));
        let local_address: SocketAddr = "127.0.0.1:8392".parse().unwrap();
        let config = FullConfig::from_protocol_groups(
            Protocol::Basic,
            local_address,
            vec![group.clone()],
            100,
            20,
            true,
        );
        let protocol = Protocol::Basic;
        let srunning = Arc::clone(&running);

        let r = tokio::spawn(receive_clipboard(
            clipboards,
            atx,
            local_address,
            Arc::clone(&running),
            config.clone(),
            protocol,
            Arc::clone(&sender),
            false,
        ));
        let s = tokio::spawn(send_clipboard(
            clipboardr,
            rx,
            Arc::clone(&running),
            config,
            Arc::clone(&sender),
            false,
        ));
        let t: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            let mut clipboard = Clipboard::new().unwrap();
            write_to(
                &mut clipboard,
                &group,
                "test1".as_bytes().to_vec(),
                &MessageType::Text,
                &"empty".into(),
            )
            .unwrap();
            sleep(Duration::from_millis(1100)).await;
            srunning.store(false, Ordering::Relaxed);
            sleep(Duration::from_millis(100)).await;
            Ok(())
        });
        match try_join!(r, s, t) {
            Ok(result) => {
                assert_eq!(result.0.unwrap(), 1);
                assert_eq!(result.1.unwrap(), 1);
            }
            Err(e) => panic!(e),
        };
    }

    #[tokio::test]
    async fn test_wait_handle_receive()
    {
        let clipboard = Clipboard::new().unwrap();
        let mut group = Group::from_addr("test1", "127.0.0.1:8393", "127.0.0.1:8394");
        group.clipboard = "/tmp/twtest1".to_owned();
        let (tx, _rx) = flume::bounded(MAX_CHANNEL);
        let atx = Arc::new(tx);
        let (stat_sender, _) = flume::bounded(MAX_CHANNEL);
        let sender = Arc::new(stat_sender);
        let running = Arc::new(AtomicBool::new(true));
        let local_address: SocketAddr = "127.0.0.1:8394".parse().unwrap();
        let config = FullConfig::from_protocol_groups(
            Protocol::Basic,
            local_address,
            vec![group.clone()],
            100,
            20,
            false,
        );
        let protocol = Protocol::Basic;
        let srunning = Arc::clone(&running);

        let r = tokio::spawn(receive_clipboard(
            clipboard,
            atx,
            local_address,
            running,
            config,
            protocol,
            sender,
            false,
        ));
        let s: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            let sent = send_clipboard_contents("test1".to_string(), &group).await;
            assert_eq!(74, sent.unwrap());
            srunning.store(false, Ordering::Relaxed);
            sleep(Duration::from_millis(100)).await;
            Ok(())
        });
        match try_join!(r, s) {
            Ok(result) => assert_eq!(result.0.unwrap(), 1),
            Err(e) => panic!(e),
        };
    }

    #[test]
    fn test_clipboard_group_to_bytes()
    {
        let mut clipboard = Clipboard::new().unwrap();
        let mut group = Group::from_name("test1");

        group.clipboard = "tests/test-dir/a".to_owned();
        let res = clipboard_group_to_bytes(&mut clipboard, &group, None);
        assert_eq!(
            res,
            Some((
                "4644417185603328019".to_owned(),
                MessageType::File,
                vec![97]
            ))
        );

        group.clipboard = CLIPBOARD_NAME.to_owned();

        clipboard
            .set_target_contents(ClipboardType::Text, b"test1")
            .unwrap();

        let res = clipboard_group_to_bytes(&mut clipboard, &group, None);
        assert_eq!(
            res,
            Some((
                "17623087596200270265".to_owned(),
                MessageType::Text,
                vec![116, 101, 115, 116, 49]
            ))
        );

        group.clipboard = "tests/test-dir/".to_owned();

        let res = clipboard_group_to_bytes(&mut clipboard, &group, None);
        assert_eq!(
            res,
            Some((
                "12908774274447230140".to_owned(),
                MessageType::Directory,
                vec![
                    2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 97, 1, 0, 0, 0, 0, 0, 0, 0, 97,
                    1, 0, 0, 0, 0, 0, 0, 0, 98, 1, 0, 0, 0, 0, 0, 0, 0, 98
                ]
            ))
        );

        group.clipboard = "tests/test-dir".to_owned();
        let res = clipboard_group_to_bytes(&mut clipboard, &group, None);
        assert_eq!(res, None);

        group.clipboard = "tests/non-existing".to_owned();
        let res = clipboard_group_to_bytes(&mut clipboard, &group, None);
        assert_eq!(res, None);
    }
}
