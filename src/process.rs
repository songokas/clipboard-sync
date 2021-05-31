use flume::{Receiver, Sender};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio::time::{sleep, Duration};

use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;

use crate::clipboards::{
    create_targets_for_cut_files, create_text_targets, Clipboard, ClipboardType,
};
use crate::config::{FullConfig, Groups};
use crate::defaults::*;
use crate::encryption::*;
use crate::errors::*;
use crate::filesystem::*;
use crate::fragmenter::{GroupsEncryptor, IdentityEncryptor};
use crate::identity::{retrieve_identity, validate, Identity};
use crate::message::*;
use crate::multicast::Multicast;
use crate::notify::{create_watch_paths, watch_changed_paths};
use crate::protocols::{receive_data, send_data, Protocol, SocketPool};
use crate::socket::*;

pub async fn receive_clipboard(
    pool: Arc<SocketPool>,
    mut clipboard: Clipboard,
    channel: Sender<(String, String)>,
    local_address: SocketAddr,
    running: Arc<AtomicBool>,
    config: FullConfig,
    protocol: Protocol,
    status_channel: Sender<(u64, u64)>,
    receive_once: bool,
) -> Result<(String, u64), CliError>
{
    let local_socket = match pool
        .obtain_server_socket(local_address.clone(), &protocol)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            running.store(false, Ordering::Relaxed);
            return Err(CliError::from(e));
        }
    };
    let mut multicast = Multicast::new();
    let mut count = 0;
    let groups = config.groups;
    let encryptor = GroupsEncryptor::new(groups.clone());

    info!("Listen on {} protocol {}", local_address, protocol);

    if let Some(s) = local_socket.socket() {
        multicast
            .join_groups(&s, &groups, &s.local_addr()?.ip())
            .await;
    }

    let timeout = |_: Duration| !running.load(Ordering::Relaxed);
    let mut last_error = None;

    while running.load(Ordering::Relaxed) {
        let (buf, addr) = match receive_data(
            Arc::clone(&local_socket),
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
                return Err(CliError::ArgumentError(e));
            }
            Err(ConnectionError::IoError(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => {
                error!("Error receiving: {}", e);
                continue;
            }
        };

        count += 1;

        let len = buf.len();

        debug!("Packet received from {} length {}", addr, len);

        // in ipv6 sockets ipv4 mapped address should be use as ipv4 address

        let result = handle_receive(
            &mut clipboard,
            &buf[..len],
            &Identity::from_mapped(&addr),
            &groups,
            config.max_file_size,
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

            Err(err) => {
                error!("{}", err);
                last_error = Some(CliError::ClipboardError(err));
            }
        };
        if let Err(_) = status_channel.try_send((0, count)) {
            // debug!("Unable to send status count {}", e);
        }

        if receive_once {
            running.store(false, Ordering::Relaxed);
            if let Some(err) = last_error {
                return Err(err);
            }
            info!("Waiting for {} seconds", config.receive_once_wait);
            sleep(Duration::from_secs(config.receive_once_wait)).await;
            break;
        }
    }
    return Ok((format!("{} received", protocol), count));
}

pub async fn send_clipboard(
    pool: Arc<SocketPool>,
    mut clipboard: Clipboard,
    channel: Receiver<(String, String)>,
    running: Arc<AtomicBool>,
    config: FullConfig,
    status_channel: Sender<(u64, u64)>,
    send_once: bool,
) -> Result<(String, u64), CliError>
{
    let mut hash_cache: HashMap<String, String> = HashMap::new();
    let mut heartbeat_cache: HashMap<String, Instant> = HashMap::new();
    let mut count = 0;
    let groups = config.groups;

    info!("Listen for clipboard changes");

    let timeout = |_: Duration| !running.load(Ordering::Relaxed);
    let mut last_error = None;

    let mut paths_to_watch: HashMap<PathBuf, Vec<&str>> = HashMap::new();

    for (_, group) in &groups {
        let key = PathBuf::from(&group.clipboard);
        paths_to_watch
            .entry(key)
            .and_modify(|v| v.push(group.name.as_ref()))
            .or_insert(vec![group.name.as_ref()]);
    }
    let mut watcher = create_watch_paths(&paths_to_watch);

    let hash_update = |hash_cache: &mut HashMap<String, String>| {
        while let Ok((group_name, rhash)) = channel.try_recv() {
            let current_hash = match hash_cache.get(&group_name) {
                Some(val) => val.clone(),
                None => "".to_owned(),
            };
            if &current_hash != &rhash {
                hash_cache.insert(group_name.clone(), rhash.clone());
                debug!(
                    "Client updated current hash {} to {} for group {}",
                    current_hash, rhash, group_name
                );
            }
        }
    };

    while running.load(Ordering::Relaxed) {
        if let Ok((ref mut watcher, ref receiver)) = watcher {
            for (_, group_names) in watch_changed_paths(watcher, receiver, &paths_to_watch) {
                for group_name in group_names {
                    hash_cache.insert(group_name.to_owned().to_string(), "".to_owned());
                }
            }
        }

        hash_update(&mut hash_cache);

        for (_, group) in &groups {
            let (hash, message_type, bytes) = match clipboard_group_to_bytes(
                &mut clipboard,
                group,
                hash_cache.get(&group.name),
                config.max_file_size,
            ) {
                Some((hash, message_type, bytes)) if bytes.len() > 0 => (hash, message_type, bytes),
                _ => {
                    if group.heartbeat > 0 {
                        send_heartbeat(&pool, &group, &mut heartbeat_cache, timeout).await;
                    }

                    continue;
                }
            };
            hash_update(&mut hash_cache);

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

            match send_clipboard_to_group(&pool, &data, &message_type, &group, timeout).await {
                Ok(sent) if sent > 0 => {
                    debug!("Sent bytes {}", sent);
                    count += 1;
                }
                Ok(_) => (),
                Err(err) => {
                    error!("Error sending: {}", err);
                    last_error = Some(err);
                }
            };

            if let Err(_) = status_channel.try_send((count, 0)) {
                // debug!("Unable to send status count {}", e);
            }
        }
        if send_once {
            running.store(false, Ordering::Relaxed);
            if let Some(err) = last_error {
                return Err(CliError::ClipboardError(err));
            }
            break;
        }

        sleep(Duration::from_millis(500)).await;
    }
    return Ok((format!("sent"), count));
}

pub async fn send_clipboard_contents(
    pool: &SocketPool,
    contents: String,
    group: &Group,
) -> Result<usize, String>
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

    let sent = match send_clipboard_to_group(pool, &data, &message_type, &group, timeout).await {
        Ok(sent) => {
            debug!("Sent bytes {}", sent);
            sent
        }
        Err(err) => {
            error!("{}", err);
            return Err(format!("{}", err));
        }
    };
    return Ok(sent);
}

async fn send_heartbeat(
    pool: &SocketPool,
    group: &Group,
    heartbeat_cache: &mut HashMap<String, Instant>,
    timeout: impl Fn(Duration) -> bool,
)
{
    heartbeat_cache
        .entry(group.name.clone())
        .or_insert(Instant::now());

    let last = heartbeat_cache[&group.name];
    if last.elapsed().as_secs() >= group.heartbeat {
        let data = last.elapsed().as_secs().to_be_bytes();
        heartbeat_cache.insert(group.name.clone(), Instant::now());
        match send_clipboard_to_group(pool, &data, &MessageType::Heartbeat, &group, timeout).await {
            Ok(sent) => debug!("Sent heartbeat bytes {}", sent),
            Err(err) => error!("Error heartbeat: {}", err),
        };
    }
}

fn clipboard_group_to_bytes(
    clipboard: &mut Clipboard,
    group: &Group,
    existing_hash: Option<&String>,
    max_file_size: usize,
) -> Option<(String, MessageType, Vec<u8>)>
{
    if group.clipboard == CLIPBOARD_NAME {
        return clipboard_to_bytes(clipboard, existing_hash, max_file_size);
    } else if Path::new(&group.clipboard).exists() {
        if let Some(h) = existing_hash {
            if h.len() > 0 {
                return None;
            }
        }
        if Path::new(&group.clipboard).is_dir() {
            match dir_to_bytes(&group.clipboard, max_file_size) {
                Ok(bytes) => return Some((hash(&bytes), MessageType::Directory, bytes)),
                Err(_) => return None,
            };
        }
        match read_file(&group.clipboard, max_file_size) {
            Ok((bytes, full)) if full => return Some((hash(&bytes), MessageType::File, bytes)),
            Ok(_) => {
                warn!(
                    "Unable to read file {} file is larger than {}",
                    &group.clipboard, max_file_size
                );
                return None;
            }
            Err(_) => return None,
        };
    }
    return None;
}

fn clipboard_to_bytes(
    clipboard: &mut Clipboard,
    existing_hash: Option<&String>,
    max_file_size: usize,
) -> Option<(String, MessageType, Vec<u8>)>
{
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
            return Some((
                hash,
                MessageType::Files,
                files_to_bytes(files, max_file_size).ok()?,
            ));
        }
        _ => {
            match clipboard.get_target_contents(ClipboardType::Text) {
                Ok(contents) => {
                    let hash = hash(&contents);
                    if let Some(h) = existing_hash {
                        if h == &hash {
                            return None;
                        }
                    }
                    return Some((hash, MessageType::Text, contents));
                }
                _ => {
                    warn!("Failed to retrieve contents");
                    return None;
                }
            };
        }
    };
}

fn handle_receive(
    clipboard: &mut Clipboard,
    buffer: &[u8],
    identity: &Identity,
    groups: &Groups,
    max_file_size: usize,
) -> Result<(String, String), ClipboardError>
{
    let (message, group) = validate(buffer, groups, identity)?;
    let bytes = decrypt(&message, identity, &group)?;
    let data = match message.message_type {
        MessageType::Heartbeat => bytes,
        _ => uncompress(bytes)?,
    };
    return write_to(
        clipboard,
        &group,
        data,
        &message.message_type,
        identity,
        max_file_size,
    );
}

fn write_to(
    clipboard: &mut Clipboard,
    group: &Group,
    data: Vec<u8>,
    message_type: &MessageType,
    identity: &Identity,
    max_file_size: usize,
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
                let files_created =
                    bytes_to_dir(&config_path, data, &identity.to_string(), max_file_size)?;
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
    } else if group.clipboard.ends_with("/") || Path::new(&group.clipboard).is_dir() {
        let hash = hash(&data);
        bytes_to_dir(&group.clipboard, data, &identity.to_string(), max_file_size)?;
        return Ok((hash, group.name.clone()));
    }
    let hash = hash(&data);
    write_file(&group.clipboard, data, 0o600)?;
    return Ok((hash, group.name.clone()));
}

async fn send_clipboard_to_group(
    pool: &SocketPool,
    buffer: &[u8],
    message_type: &MessageType,
    group: &Group,
    //@TODO use _timeout_callback
    _timeout_callback: impl Fn(Duration) -> bool,
) -> Result<usize, ClipboardError>
{
    let mut sent = 0;
    let callback = |d: Duration| d > Duration::from_millis(2000);

    for remote_host in &group.allowed_hosts {
        let addr = match to_socket_address(remote_host) {
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
        let identity = retrieve_identity(&addr, group).await?;
        let local_socket = pool
            .obtain_client_socket(&group.send_using_address, &addr, &group.protocol)
            .await?;

        let bytes = encrypt_to_bytes(&buffer, &identity, group, message_type)?;

        debug!(
            "Sending to {}:{} using {}",
            remote_ip,
            addr.port(),
            identity
        );

        let encryptor = IdentityEncryptor::new(group.clone(), identity);
        let host = remote_host
            .strip_suffix(&format!(":{}", addr.port()))
            .unwrap_or(remote_host);

        sent += send_data(
            local_socket,
            encryptor,
            &group.protocol,
            Destination::new(host.to_owned(), addr),
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
    use indexmap::{indexmap, indexset};
    use tokio::task::JoinHandle;
    use tokio::try_join;

    #[test]
    fn test_handle_clipboard_change()
    {
        let pool = SocketPool::new();
        let timeout = |d: Duration| d > Duration::from_millis(2000);
        let result = wait!(send_clipboard_to_group(
            &pool,
            b"test",
            &MessageType::Text,
            &Group::from_name("me"),
            timeout,
        ));
        assert_eq!(result.unwrap(), 0);

        let result = wait!(send_clipboard_to_group(
            &pool,
            b"test",
            &MessageType::Text,
            &Group::from_addr("me", "127.0.0.1:0", "127.0.0.1:8093"),
            timeout,
        ));
        assert_eq!(result.unwrap(), 82);

        let result = wait!(send_clipboard_to_group(
            &pool,
            b"test",
            &MessageType::Text,
            &Group::from_addr("me", "127.0.0.1:8801", "127.0.0.1:0"),
            timeout,
        ));
        assert_eq!(result.unwrap(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_send_clipboard()
    {
        // env_logger::from_env(env_logger::Env::default().default_filter_or("debug")).init();
        let clipboards = Clipboard::new().unwrap();
        let clipboardr = Clipboard::new().unwrap();
        let mut group = Group::from_addr("test1", "127.0.0.1:8391", "127.0.0.1:8392");
        group.clipboard = "/tmp/twtest1".to_owned();
        let (tx, rx) = flume::bounded(MAX_CHANNEL);
        let (stat_sender, _) = flume::bounded(MAX_CHANNEL);
        let running = Arc::new(AtomicBool::new(true));
        let local_address: SocketAddr = "127.0.0.1:8392".parse().unwrap();
        let config = FullConfig::from_protocol_groups(
            Protocol::Basic,
            indexset! {local_address},
            indexmap! { group.name.clone() => group.clone() },
            100,
            100,
            20,
            true,
            None,
        );
        let protocol = Protocol::Basic;
        let srunning = Arc::clone(&running);
        let pool = Arc::new(SocketPool::new());

        let r = tokio::spawn(receive_clipboard(
            pool.clone(),
            clipboards,
            tx,
            local_address,
            Arc::clone(&running),
            config.clone(),
            protocol,
            stat_sender.clone(),
            false,
        ));
        let s = tokio::spawn(send_clipboard(
            pool.clone(),
            clipboardr,
            rx,
            Arc::clone(&running),
            config,
            stat_sender.clone(),
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
                100,
            )
            .unwrap();
            sleep(Duration::from_millis(1100)).await;
            srunning.store(false, Ordering::Relaxed);
            sleep(Duration::from_millis(100)).await;
            Ok(())
        });
        match try_join!(r, s, t) {
            Ok(result) => {
                assert_eq!(result.0.unwrap().1, 1);
                assert_eq!(result.1.unwrap().1, 1);
            }
            Err(_) => panic!("failed to join"),
        };
    }

    #[tokio::test]
    async fn test_receive_clipboard()
    {
        let clipboard = Clipboard::new().unwrap();
        let mut group = Group::from_addr("test1", "127.0.0.1:8393", "127.0.0.1:8394");
        group.clipboard = "/tmp/twtest1".to_owned();
        let (tx, _rx) = flume::bounded(MAX_CHANNEL);
        let (stat_sender, _) = flume::bounded(MAX_CHANNEL);
        let running = Arc::new(AtomicBool::new(true));
        let local_address: SocketAddr = "127.0.0.1:8394".parse().unwrap();
        let config = FullConfig::from_protocol_groups(
            Protocol::Basic,
            indexset! {local_address},
            indexmap! { group.name.clone() => group.clone() },
            100,
            100,
            20,
            false,
            None,
        );
        let protocol = Protocol::Basic;
        let srunning = Arc::clone(&running);
        let pool = Arc::new(SocketPool::new());

        let r = tokio::spawn(receive_clipboard(
            pool.clone(),
            clipboard,
            tx,
            local_address,
            running,
            config,
            protocol,
            stat_sender,
            false,
        ));
        let s: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            let sent = send_clipboard_contents(&pool, "test1".to_string(), &group).await;
            assert_eq!(94, sent.unwrap());
            // let server handle it
            sleep(Duration::from_millis(4000)).await;
            srunning.store(false, Ordering::Relaxed);
            sleep(Duration::from_millis(1000)).await;
            Ok(())
        });
        match try_join!(r, s) {
            Ok(result) => assert_eq!(result.0.unwrap().1, 1),
            Err(_) => panic!("failed to join"),
        };
    }

    #[test]
    fn test_clipboard_group_to_bytes()
    {
        let mut clipboard = Clipboard::new().unwrap();
        let mut group = Group::from_name("test1");

        group.clipboard = "tests/test-dir/a".to_owned();
        let res = clipboard_group_to_bytes(&mut clipboard, &group, None, 100);
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

        let res = clipboard_group_to_bytes(&mut clipboard, &group, None, 100);
        assert_eq!(
            res,
            Some((
                "17623087596200270265".to_owned(),
                MessageType::Text,
                vec![116, 101, 115, 116, 49]
            ))
        );

        group.clipboard = "tests/test-dir/".to_owned();

        let res = clipboard_group_to_bytes(&mut clipboard, &group, None, 100);
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

        let res = clipboard_group_to_bytes(&mut clipboard, &group, None, 100);
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

        group.clipboard = "tests/non-existing".to_owned();
        let res = clipboard_group_to_bytes(&mut clipboard, &group, None, 100);
        assert_eq!(res, None);
    }

    #[test]
    fn test_path_buf_comparison()
    {
        assert!(PathBuf::from("/tmp/") == PathBuf::from("/tmp"));
        assert!(Path::new("/tmp/").is_dir());
    }
}
