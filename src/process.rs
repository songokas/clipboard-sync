use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use bincode;
use std::io;
use std::iter::Iterator;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::net::{UdpSocket};
use tokio::time::{sleep, Duration};
use tokio::sync::mpsc::{Sender, Receiver};

use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;

use crate::encryption::*;
use crate::errors::*;
use crate::message::*;

const MAX_CLIPBOARD: usize = 1432;

fn set_clipboard(contents: &str) -> Result<(), ClipboardError>
{
    let mut ctx: ClipboardContext =
        ClipboardProvider::new().map_err(|err| ClipboardError::Provider((*err).to_string()))?;
    ctx.set_contents(contents.to_owned())
        .map_err(|err| ClipboardError::Access((*err).to_string()))?;
    return Ok(());
}

fn validate(buffer: &[u8], groups: &[Group]) -> Result<(Message, Group), ValidationError>
{
    let message: Message = bincode::deserialize(buffer)
        .map_err(|err| ValidationError::DeserializeFailed((*err).to_string()))?;
    let group = match groups.iter().find(|group| group.name == message.group) {
        Some(group) => group,
        _ => {
            return Err(ValidationError::IncorrectGroup(format!(
                "Group {} does not exist",
                message.group
            )));
        }
    };
    return Ok((message, group.clone()));
}


fn on_receive(buffer: &[u8], identity: &str, groups: &[Group]) -> Result<String, ClipboardError>
{
    let (message, group) = validate(buffer, groups)?;
    let contents = decrypt(&message, identity, &group)?;
    set_clipboard(&contents)?;
    Ok(contents)
}

async fn obtain_socket(local_address: &SocketAddr, remote_addr: &SocketAddr) -> Result<UdpSocket, ConnectionError>
{
    debug!("Send to {} using {}", remote_addr, local_address);
    let sock = UdpSocket::bind(local_address).await?;
    sock.connect(remote_addr).await?;
    return Ok(sock);
}

fn obtain_local_addr(sock: &UdpSocket) -> Result<IpAddr, ConnectionError>
{
    return sock.local_addr()
            .map(|s| s.ip().clone() )
            .map_err(|err| ConnectionError::IoError(err));
}

async fn on_clipboard_change(contents: &str, groups: &[Group]) -> Result<usize, ClipboardError>
{
    let mut sent = 0;
    for group in groups {
        for addr in &group.allowed_hosts {

            let sock = obtain_socket(&group.send_using_address, addr).await?;
            let remote_ip = addr.ip();

            // @TODO cleanup
            let identity = if remote_ip.is_global() {
                group.public_ip.ok_or(
                    ConnectionError::NoPublic("Group missing public ip however global routing requested".to_owned())
                )
            } else if remote_ip.is_multicast() {
                let local_addr = obtain_local_addr(&sock)?;

                let interface_ipv4 = match local_addr {
                    IpAddr::V4(ipv4) => ipv4,
                    _ => {
                        warn!("Ipv6 multicast not supported");
                        continue;
                    }
                };

                let op = match remote_ip {
                    IpAddr::V4(multicast_ipv4) => sock.join_multicast_v4(multicast_ipv4, interface_ipv4),
                    _ => {
                        warn!("Ipv6 multicast not supported");
                        continue;
                    }
                };
                op.expect("Unable to join multicast network");
                Ok(local_addr)
            } else {
                obtain_local_addr(&sock)
            };

            let message = encrypt(&contents.as_bytes(), &identity?.to_string(), group)?;
            let bytes = bincode::serialize(&message)
                .map_err(|err| EncryptionError::SerializeFailed((*err).to_string()))?;
                
            sent += sock.send(&bytes).await
                .map_err(|err| ConnectionError::IoError(err))?;
        }
    }
    Ok(sent)
}

pub async fn wait_on_receive(
    channel: Sender<String>,
    local_address: SocketAddr,
    running: Arc<AtomicBool>,
    groups: &[Group],
) -> Result<(), io::Error>
{
    let sock = UdpSocket::bind(local_address).await?;
    let interface_ip = obtain_local_addr(&sock).expect("Unable to retrieve interface ip");
    let local_interface = match interface_ip { IpAddr::V4(ip) => Some(ip), _ => None };
    // @TODO cleanup
    if let Some(ipv4) = local_interface {
        for group in groups {
            for addr in &group.allowed_hosts {
                if addr.ip().is_multicast() {
                    let op = match addr.ip() {
                        IpAddr::V4(ip) => sock.join_multicast_v4(ip, ipv4),
                        _ => continue
                    };
                    op.expect(&format!("Unable to join {}", addr.ip()));
                }
            }
        }
    }

    let mut buf = [0; MAX_CLIPBOARD];
    while running.load(Ordering::Relaxed) {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        debug!("Packet received from {} length {}", addr, len);
        let result = on_receive(&buf[..len], &addr.ip().to_string(), groups);
        match result {
            Ok(contents) => {
                if let Err(msg) = channel.try_send(hash(&contents)) {
                    warn!("Unable to update current hash {}", msg);
                }
            }
            Err(err) => error!("{:?}", err),
        };
    }
    Ok(())
}


pub async fn wait_on_clipboard(mut channel: Receiver<String>, running: Arc<AtomicBool>, groups: &[Group])
{
    let mut clipboard: ClipboardContext = ClipboardProvider::new().unwrap();
    let mut current_hash: String = "".to_owned();
    while running.load(Ordering::Relaxed) {
        sleep(Duration::from_millis(500)).await;
        if let Ok(rhash) = channel.try_recv() {
            debug!("Updated hash {} to {}", current_hash, rhash);
            current_hash = rhash;
        }
        let contents = match clipboard.get_contents() {
            Ok(contents) => contents,
            _ => {
                debug!("Failed to retrieve contents");
                continue;
            }
        };
        let hash = hash(&contents);
        if current_hash == "" {
            current_hash = hash.clone();
        }
        if contents != "" && hash != current_hash {
            debug!("Clipboard changed {}", &hash);
            match on_clipboard_change(&contents, groups).await {
                Ok(sent) => debug!("Sent bytes {}", sent),
                Err(err) => error!("{:?}", err),
            }
            current_hash = hash;
        }
    }
}