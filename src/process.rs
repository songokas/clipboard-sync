use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration};

use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;

use crate::defaults::*;
use crate::encryption::*;
use crate::errors::*;
use crate::filesystem::*;
use crate::message::*;
use crate::socket::*;

pub async fn wait_on_receive(
    channel: Sender<(String, String)>,
    local_address: SocketAddr,
    running: Arc<AtomicBool>,
    groups: &[Group],
) -> Result<(), CliError>
{
    let sock = UdpSocket::bind(local_address).await?;
    info!("Listen on {}", local_address);
    let interface_ip = obtain_local_addr(&sock).expect("Unable to retrieve interface ip");
    let local_interface = match interface_ip {
        IpAddr::V4(ip) => Some(ip),
        _ => None,
    };
    if let Some(ipv4) = local_interface {
        join_groups(&sock, groups, &ipv4);
    }

    // let mut buf = vec![0; MAX_RECEIVE_BUFFER];
    while running.load(Ordering::Relaxed) {
        let (buf, addr) = match receive_data(&sock, MAX_RECEIVE_BUFFER, &groups).await {
            Ok(v) => v,
            Err(_) => {
                continue;
            }
        };
        let len = buf.len();

        debug!("Packet received from {} length {}", addr, len);
        let result = on_receive(&buf[..len], &addr.ip().to_string(), groups);

        match result {
            Ok((_, hash, group_name)) => {
                if let Err(msg) = channel.try_send((group_name, hash)) {
                    warn!("Unable to update current hash {}", msg);
                }
            }
            Err(err) => error!("{:?}", err),
        };
    }
    Ok(())
}

pub async fn wait_on_clipboard(
    mut channel: Receiver<(String, String)>,
    running: Arc<AtomicBool>,
    groups: &[Group],
) -> Result<(), CliError>
{
    let mut clipboard: ClipboardContext = ClipboardProvider::new().unwrap();
    let mut hash_cache: HashMap<String, String> = HashMap::new();
    info!("Listen for clipboard changes");
    while running.load(Ordering::Relaxed) {
        //@TODO think about the events
        sleep(Duration::from_millis(1000)).await;
        if let Ok((group_name, rhash)) = channel.try_recv() {
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

        let contents = match clipboard.get_contents() {
            Ok(contents) => contents,
            _ => {
                warn!("Failed to retrieve contents");
                continue;
            }
        };

        for group in groups {
            let bytes: Vec<u8> = if group.clipboard == "clipboard" {
                contents.as_bytes().to_vec()
            } else if group.clipboard.ends_with("/") {
                match dir_to_bytes(&group.clipboard) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        error!("Error reading directory. Message: {:?}", err);
                        continue;
                    }
                }
            } else {
                match read_file(&group.clipboard, MAX_FILE_SIZE) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        error!("Error reading file {}. Message: {}", &group.clipboard, err);
                        continue;
                    }
                }
            };

            if bytes.len() == 0 {
                continue;
            }
            let hash = hash(&bytes);

            let entry_value = match hash_cache.get(&group.name) {
                Some(val) => val.to_owned(),
                None => {
                    hash_cache.insert(group.name.clone(), hash.clone());
                    hash.clone()
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

            match on_clipboard_change(&data, &group).await {
                Ok(sent) => debug!("Sent bytes {}", sent),
                Err(err) => error!("{:?}", err),
            }
        }
    }
    return Ok(());
}

fn set_clipboard(contents: &str) -> Result<(), ClipboardError>
{
    let mut ctx: ClipboardContext =
        ClipboardProvider::new().map_err(|err| ClipboardError::Provider((*err).to_string()))?;
    ctx.set_contents(contents.to_owned())
        .map_err(|err| ClipboardError::Access((*err).to_string()))?;
    return Ok(());
}

fn on_receive(
    buffer: &[u8],
    identity: &str,
    groups: &[Group],
) -> Result<(String, String, String), ClipboardError>
{
    let (message, group) = validate(buffer, groups)?;
    let bytes = decrypt(&message, identity, &group)?;
    let data = uncompress(bytes)?;
    let hash = hash(&data);
    if group.clipboard == "clipboard" {
        let contents: String = String::from_utf8(data)
            .map_err(|e| ClipboardError::Invalid(format!("Not a valid utf8 string {}", e)))?;
        set_clipboard(&contents)?;
        return Ok((contents, hash, group.name.clone()));
    } else if group.clipboard.ends_with("/") {
        bytes_to_dir(&group.clipboard, data, identity)?;
        return Ok((group.clipboard.clone(), hash, group.name.clone()));
    }
    fs::write(&group.clipboard, data)?;
    return Ok((group.clipboard.clone(), hash, group.name.clone()));
}

async fn on_clipboard_change(buffer: &[u8], group: &Group) -> Result<usize, ClipboardError>
{
    let mut sent = 0;
    for addr in &group.allowed_hosts {
        if addr.port() == 0 {
            debug!("Not sending to host {}", addr);
            continue;
        }
        let sock = obtain_socket(&group.send_using_address, addr).await?;
        let remote_ip = addr.ip();

        let identity = if remote_ip.is_multicast() {
            let local_addr = obtain_local_addr(&sock)?;
            join_group(&sock, &local_addr, &remote_ip);
            Ok(local_addr)
        } else if remote_ip.is_global() {
            group.public_ip.ok_or(ConnectionError::NoPublic(
                "Group missing public ip however global routing requested".to_owned(),
            ))
        } else {
            obtain_local_addr(&sock)
        };

        let bytes = encrypt_to_bytes(&buffer, &identity?.to_string(), group)?;
        sent += send_data(sock, bytes, addr, group).await?;
    }
    return Ok(sent);
}

#[cfg(test)]
mod socketstest
{
    use super::*;

    #[test]
    fn test_validate()
    {
        let groups = vec![Group::from_name("test1"), Group::from_name("test2")];
        let sequences: Vec<(Vec<u8>, bool)> = vec![
            (
                bincode::serialize(&Message::from_group("test1"))
                    .unwrap()
                    .to_vec(),
                true,
            ),
            (
                bincode::serialize(&Message::from_group("none"))
                    .unwrap()
                    .to_vec(),
                false,
            ),
            ([3, 3, 98].to_vec(), false),
            ([].to_vec(), false),
        ];

        for (bytes, expected) in sequences {
            let result = validate(&bytes, &groups);
            assert_eq!(result.is_ok(), expected);
        }
    }
}
