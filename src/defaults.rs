use core::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use crate::{errors::CliError, message::AllowedHosts, protocol::Protocol};

pub const BIND_ADDRESS: &str = "0.0.0.0:8900";
// pub const BIND_ADDRESS_IPV6: &str = "0.0.0.0:8900,[::]:8900";
// pub const BIND_ADDRESS_IPV6_ONLY: &str = "[::]:8900";
pub const SEND_ADDRESS: &str = "0.0.0.0:0";
pub const SEND_ADDRESS_IPV6: &str = "0.0.0.0:0,[::]:0";
pub const DEFAULT_ALLOWED_HOST: &str = "224.0.2.89:8900";
pub const DEFAULT_QUIC_ALLOWED_HOST: &str = "224.0.2.89:8901";
// pub const DEFAULT_ALLOWED_HOST_IPV6: &str = "[ff02:1000:1000:dada::1%3]:8900";
pub const DEFAULT_GROUP: &str = "default";
pub const CLIPBOARD_NAME: &str = "clipboard";
pub const DEFAULT_CLIPBOARD: &str = "default-clipboard";
pub const DEFAULT_PROTOCOL: &str = "basic";
pub const PACKAGE_NAME: &str = "clipboard-sync";
pub const MAX_CHANNEL: usize = 100;
pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24;
pub const MAX_FILE_SIZE: usize = 22 * 1024 * 1024;
pub const MAX_RECEIVE_BUFFER: usize = 50 * 1024 * 1024;
#[cfg(target_os = "macos")]
pub const MAX_UDP_PAYLOAD: usize = 9216;
#[cfg(not(target_os = "macos"))]
pub const MAX_UDP_PAYLOAD: usize = 63535;
pub const MAX_UDP_BUFFER: usize = 64135;
pub const MAX_CONNECTIONS: usize = 100;

pub const DATA_TIMEOUT: Duration = Duration::from_secs(12);
pub const WAIT_TIMEOUT: Duration = Duration::from_secs(60);
pub const RECEIVE_ONCE_WAIT: Duration = Duration::from_secs(45);
pub const RECEIVE_ONCE_WAIT_STR_SECS: &str = "45";

// pub const NTP_SERVER: &str = "0.pool.ntp.org:123";
pub const MESSAGE_VALID_DURATION: Duration = Duration::from_secs(300);
pub const MESSAGE_VALID_FOR_STR_SECS: &str = "300";

pub const DEFAULT_RELAY_MESSAGE_SIZE: usize = 144;
pub const INIDICATION_SIZE: usize = std::mem::size_of::<u64>();
pub const PUBLIC_IP_HTTP_RESOLVER: &str = "ifconfig.me:80";
pub const UNKNOWN_SOCKET_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

pub type ExecutorResult = Result<(&'static str, u64), CliError>;

pub fn get_default_hosts(protocol: Protocol) -> AllowedHosts {
    let host = match protocol {
        Protocol::Quic => DEFAULT_QUIC_ALLOWED_HOST,
        _ => DEFAULT_ALLOWED_HOST,
    };
    let mut hosts = AllowedHosts::new();
    hosts.insert(host.to_string(), None);
    hosts
}
