use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration};

#[cfg(feature = "clipboard")]
use clipboard::ClipboardProvider;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;

use crate::config::FullConfig;
use crate::defaults::*;
use crate::encryption::*;
use crate::errors::*;
use crate::filesystem::*;
use crate::message::*;
use crate::protocols::*;
use crate::socket::*;

pub async fn wait_handle_receive(
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
    let mut endpoint = obtain_server_socket(&local_address, &protocol).await?;
    let interface_ip = endpoint.ip();
    let mut multicast = Multicast::new();
    let mut count = 0;
    let groups = config.groups;

    info!("Listen on {}", local_address);

    if let Some(local_addr) = interface_ip {
        if let Some(sock) = endpoint.socket() {
            multicast.join_groups(sock, &groups, &local_addr).await;
        }
    }

    let timeout = |_: Duration| !running.load(Ordering::Relaxed);

    while running.load(Ordering::Relaxed) {
        let (buf, addr) = match receive_data(
            &mut endpoint,
            config.max_receive_buffer,
            &groups,
            &protocol,
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

        let result = handle_receive(&buf[..len], &addr.ip().to_string(), &groups, &mut clipboard);

        match result {
            Ok((_, hash, group_name)) => {
                if let Err(msg) = channel.try_send((group_name, hash)) {
                    warn!("Unable to update current hash {}", msg);
                }
            }
            Err(err) => error!("{:?}", err),
        };
        if let Err(e) = status_channel.try_send((0, count)) {
            debug!("Unable to send status count {}", e);
        }

        if receive_once {
            running.store(false, Ordering::Relaxed);
            break;
        }
    }
    return Ok(count);
}

pub async fn wait_on_clipboard(
    mut clipboard: Clipboard,
    mut channel: Receiver<(String, String)>,
    running: Arc<AtomicBool>,
    config: FullConfig,
    status_channel: Arc<Sender<(u64, u64)>>,
    send_once: bool,
) -> Result<u64, CliError>
{
    let mut hash_cache: HashMap<String, String> = HashMap::new();
    let mut count = 0;
    let groups = config.groups;

    info!("Listen for clipboard changes");

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
            let bytes = match clipboard_group_to_bytes(&mut clipboard, group) {
                Some(b) if b.len() > 0 => b,
                _ => continue,
            };

            let hash = hash(&bytes);

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

            let mut multicast = Multicast::new();
            match handle_clipboard_change(&data, &group, &mut multicast).await {
                Ok(sent) => debug!("Sent bytes {}", sent),
                Err(err) => error!("{:?}", err),
            };

            if let Err(e) = status_channel.try_send((count, 0)) {
                debug!("Unable to send status count {}", e);
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

pub async fn send_clipboard(contents: String, group: &Group) -> Result<usize, String>
{
    let mut multicast = Multicast::new();
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

    let sent = match handle_clipboard_change(&data, &group, &mut multicast).await {
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

fn clipboard_group_to_bytes(clipboard: &mut Clipboard, group: &Group) -> Option<Vec<u8>>
{
    let bytes: Vec<u8> = if group.clipboard == "clipboard" {
        let contents = match clipboard.get_contents() {
            Ok(contents) => contents,
            _ => {
                warn!("Failed to retrieve contents");
                return None;
            }
        };
        contents.as_bytes().to_vec()
    } else if group.clipboard.ends_with("/") {
        match dir_to_bytes(&group.clipboard) {
            Ok(bytes) => bytes,
            Err(_) => {
                return None;
            }
        }
    } else {
        match read_file(&group.clipboard, MAX_FILE_SIZE) {
            Ok(bytes) => bytes,
            Err(_) => {
                return None;
            }
        }
    };
    return Some(bytes);
}

fn handle_receive(
    buffer: &[u8],
    identity: &str,
    groups: &[Group],
    clipboard: &mut Clipboard,
) -> Result<(String, String, String), ClipboardError>
{
    let (message, group) = validate(buffer, groups)?;
    let bytes = decrypt(&message, identity, &group)?;
    let data = uncompress(bytes)?;
    return write_to(clipboard, &group, data, identity);
}

fn write_to(
    clipboard: &mut Clipboard,
    group: &Group,
    data: Vec<u8>,
    identity: &str,
) -> Result<(String, String, String), ClipboardError>
{
    let hash = hash(&data);
    if group.clipboard == "clipboard" {
        let contents: String = String::from_utf8(data)
            .map_err(|e| ClipboardError::Invalid(format!("Not a valid utf8 string {}", e)))?;
        clipboard
            .set_contents(contents.to_owned())
            .map_err(|err| ClipboardError::Access((*err).to_string()))?;
        return Ok((contents, hash, group.name.clone()));
    } else if group.clipboard.ends_with("/") {
        bytes_to_dir(&group.clipboard, data, identity)?;
        return Ok((group.clipboard.clone(), hash, group.name.clone()));
    }
    fs::write(&group.clipboard, data)?;
    return Ok((group.clipboard.clone(), hash, group.name.clone()));
}

async fn handle_clipboard_change(
    buffer: &[u8],
    group: &Group,
    multicast: &mut Multicast,
) -> Result<usize, ClipboardError>
{
    let mut sent = 0;
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
        let endpoint =
            obtain_client_socket(&group.send_using_address, addr, &group.protocol).await?;

        let identity = retrieve_identity(&remote_ip, endpoint.ip(), group).await?;
        let bytes = encrypt_to_bytes(&buffer, &identity.to_string(), group)?;

        if remote_ip.is_multicast() {
            if let Some(sock) = endpoint.socket() {
                multicast.join_group(sock, &identity, &remote_ip);
            }
        }
        sent += send_data(endpoint, bytes, &addr, group).await?;
    }
    return Ok(sent);
}

async fn retrieve_identity(
    remote_ip: &IpAddr,
    local_ip: Option<IpAddr>,
    group: &Group,
) -> Result<IpAddr, ConnectionError>
{
    let is_private = match remote_ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        //@TODO ipv6 private in stable
        _ => false,
    };

    let identity = if remote_ip.is_multicast() {
        match group.protocol {
            Protocol::Basic => (),
            _ => {
                return Err(ConnectionError::InvalidProtocol(format!(
                    "Protocol {} does not support multicast",
                    group.protocol
                )));
            }
        };
        let local_addr = local_ip.unwrap_or(group.send_using_address.ip());
        local_addr
    } else if remote_ip.is_loopback() || is_private {
        local_ip.unwrap_or(group.send_using_address.ip())
    } else {
        let host = group.public_ip.as_ref().ok_or(ConnectionError::NoPublic(
            "Group missing public ip however global routing requested".to_owned(),
        ))?;
        let sock_addr = to_socket(host).await?;
        sock_addr.ip()
    };
    return Ok(identity);
}

#[cfg(test)]
mod processtest
{
    use super::*;
    use crate::errors::{ClipboardError, ConnectionError};
    use crate::message::Group;
    use crate::socket::Multicast;
    use crate::{assert_error_type, wait};
    use tokio::sync::mpsc::channel;
    use tokio::task::JoinHandle;
    use tokio::try_join;

    #[test]
    fn test_handle_clipboard_change()
    {
        let mut multicast = Multicast::new();
        let result = wait!(handle_clipboard_change(
            b"test",
            &Group::from_name("me"),
            &mut multicast,
        ));
        assert_eq!(result.unwrap(), 0);

        let result = wait!(handle_clipboard_change(
            b"test",
            &Group::from_addr("me", "127.0.0.1:8801", "127.0.0.1:8093"),
            &mut multicast,
        ));
        assert_eq!(result.unwrap(), 58);

        let result = wait!(handle_clipboard_change(
            b"test",
            &Group::from_addr("me", "127.0.0.1:8801", "127.0.0.1:0"),
            &mut multicast,
        ));
        assert_eq!(result.unwrap(), 0);

        let result = wait!(handle_clipboard_change(
            b"test",
            &Group::from_addr("me", "0.0.0.0:8801", "1.1.1.1:8093"),
            &mut multicast,
        ));
        assert_error_type!(
            result,
            ClipboardError::ConnectionError(ConnectionError::NoPublic(_))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_wait_on_clipboard()
    {
        // env_logger::from_env(env_logger::Env::default().default_filter_or("debug")).init();
        let clipboards = Clipboard::new().unwrap();
        let clipboardr = Clipboard::new().unwrap();
        let mut group = Group::from_addr("test1", "127.0.0.1:8391", "127.0.0.1:8392");
        group.clipboard = "/tmp/twtest1".to_owned();
        let (tx, rx) = channel(MAX_CHANNEL);
        let atx = Arc::new(tx);
        let (stat_sender, _) = channel(MAX_CHANNEL);
        let sender = Arc::new(stat_sender);
        let running = Arc::new(AtomicBool::new(true));
        let local_address: SocketAddr = "127.0.0.1:8392".parse().unwrap();
        let config = FullConfig::from_protocol_groups(
            Protocol::Basic,
            local_address,
            vec![group.clone()],
            100,
            true,
        );
        let protocol = Protocol::Basic;
        let srunning = Arc::clone(&running);

        let r = tokio::spawn(wait_handle_receive(
            clipboards,
            atx,
            local_address,
            Arc::clone(&running),
            config.clone(),
            protocol,
            Arc::clone(&sender),
            false,
        ));
        let s = tokio::spawn(wait_on_clipboard(
            clipboardr,
            rx,
            Arc::clone(&running),
            config,
            Arc::clone(&sender),
            false,
        ));
        let t: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            let mut clipboard = Clipboard::new().unwrap();
            write_to(&mut clipboard, &group, "test1".as_bytes().to_vec(), "empty").unwrap();
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
        let (tx, _rx) = channel(MAX_CHANNEL);
        let atx = Arc::new(tx);
        let (stat_sender, _) = channel(MAX_CHANNEL);
        let sender = Arc::new(stat_sender);
        let running = Arc::new(AtomicBool::new(true));
        let local_address: SocketAddr = "127.0.0.1:8394".parse().unwrap();
        let config = FullConfig::from_protocol_groups(
            Protocol::Basic,
            local_address,
            vec![group.clone()],
            100,
            false,
        );
        let protocol = Protocol::Basic;
        let srunning = Arc::clone(&running);

        let r = tokio::spawn(wait_handle_receive(
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
            let sent = send_clipboard("test1".to_string(), &group).await;
            assert_eq!(70, sent.unwrap());
            srunning.store(false, Ordering::Relaxed);
            sleep(Duration::from_millis(100)).await;
            Ok(())
        });
        match try_join!(r, s) {
            Ok(result) => assert_eq!(result.0.unwrap(), 1),
            Err(e) => panic!(e),
        };
    }
    // #[test]
    // fn test_send_clipboard () { }

    #[test]
    fn test_clipboard_group_to_bytes()
    {
        let mut clipboard = Clipboard::new().unwrap();
        let mut group = Group::from_name("test1");

        group.clipboard = "tests/test-dir/a".to_owned();
        let res = clipboard_group_to_bytes(&mut clipboard, &group);
        assert_eq!(res, Some(vec![97]));

        group.clipboard = "clipboard".to_owned();

        clipboard.set_contents("test1".to_owned()).unwrap();

        let res = clipboard_group_to_bytes(&mut clipboard, &group);
        assert_eq!(res, Some(vec![116, 101, 115, 116, 49]));

        group.clipboard = "tests/test-dir/".to_owned();

        let res = clipboard_group_to_bytes(&mut clipboard, &group);
        assert_eq!(
            res,
            Some(vec![
                2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 97, 1, 0, 0, 0, 0, 0, 0, 0, 97, 1,
                0, 0, 0, 0, 0, 0, 0, 98, 1, 0, 0, 0, 0, 0, 0, 0, 98
            ])
        );

        group.clipboard = "tests/test-dir".to_owned();
        let res = clipboard_group_to_bytes(&mut clipboard, &group);
        assert_eq!(res, None);

        group.clipboard = "tests/non-existing".to_owned();
        let res = clipboard_group_to_bytes(&mut clipboard, &group);
        assert_eq!(res, None);
    }

    fn identity_provider() -> Vec<(IpAddr, IpAddr, Option<IpAddr>, Group)>
    {
        return vec![
            (
                "127.0.0.2".parse().unwrap(),
                "192.168.0.1".parse().unwrap(),
                Some("127.0.0.2".parse().unwrap()),
                Group::from_name("test1"),
            ),
            (
                "127.0.0.2".parse().unwrap(),
                "172.16.0.1".parse().unwrap(),
                Some("127.0.0.2".parse().unwrap()),
                Group::from_name("test2"),
            ),
            (
                "127.0.0.2".parse().unwrap(),
                "224.0.0.1".parse().unwrap(),
                Some("127.0.0.2".parse().unwrap()),
                Group::from_name("test3"),
            ),
            (
                "127.0.0.2".parse().unwrap(),
                "169.254.0.1".parse().unwrap(),
                Some("127.0.0.2".parse().unwrap()),
                Group::from_name("test4"),
            ),
            (
                "127.0.0.3".parse().unwrap(),
                "169.254.0.1".parse().unwrap(),
                None,
                Group::from_addr("test5", "127.0.0.3:9811", "192.168.0.1"),
            ),
            (
                "192.168.0.1".parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
                Some("192.168.0.1".parse().unwrap()),
                Group::from_name("test4"),
            ),
            (
                "192.168.0.1".parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
                None,
                Group::from_addr("test5", "192.168.0.1:9811", "192.168.0.1"),
            ),
            (
                "8.8.8.8".parse().unwrap(),
                "1.1.1.1".parse().unwrap(),
                Some("127.0.0.1".parse().unwrap()),
                Group::from_public("test4", "8.8.8.8:8898"),
            ),
        ];
    }

    #[test]
    fn test_retrieve_identity()
    {
        for (expected, remote_ip, local_ip, group) in identity_provider() {
            let res = wait!(retrieve_identity(&remote_ip, local_ip, &group));
            assert_eq!(expected, res.unwrap());
        }
    }

    #[test]
    fn test_retrieve_identity_errors()
    {
        let r1 = (
            "1.1.1.1".parse().unwrap(),
            Some("127.0.0.1".parse().unwrap()),
            Group::from_public("test1", "8.8.8.8"),
        );
        let res = wait!(retrieve_identity(&r1.0, r1.1, &r1.2));
        assert_error_type!(res, ConnectionError::DnsError(_));

        let r1 = (
            "1.1.1.1".parse().unwrap(),
            Some("127.0.0.1".parse().unwrap()),
            Group::from_public("test2", "abc"),
        );
        let res = wait!(retrieve_identity(&r1.0, r1.1, &r1.2));
        assert_error_type!(res, ConnectionError::DnsError(_));

        #[cfg(feature = "frames")]
        {
            let mut g = Group::from_name("test3");
            g.protocol = Protocol::Frames;
            let r1 = (
                "224.0.0.1".parse().unwrap(),
                Some("127.0.0.1".parse().unwrap()),
                g,
            );
            let res = wait!(retrieve_identity(&r1.0, r1.1, &r1.2));
            assert_error_type!(res, ConnectionError::InvalidProtocol(_));
        }

        let r1 = (
            "1.1.1.1".parse().unwrap(),
            Some("127.0.0.1".parse().unwrap()),
            Group::from_name("test5"),
        );
        let res = wait!(retrieve_identity(&r1.0, r1.1, &r1.2));
        assert_error_type!(res, ConnectionError::NoPublic(_));
    }
}
