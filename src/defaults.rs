use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const BIND_ADDRESS: &str = "0.0.0.0:8900";
pub const SEND_ADDRESS: &str = "0.0.0.0:8901";
pub const DEFAULT_GROUP: &str = "default";
pub const DEFAULT_CLIPBOARD: &str = "clipboard";
pub const DEFAULT_ALLOWED_HOST: &str = "224.0.0.89:8900";
pub const MAX_CHANNEL: usize = 100;
pub const KEY_SIZE: usize = 32;
pub const MAX_FILE_SIZE: usize = 10 * 1024 * 1024;
pub const MAX_RECEIVE_BUFFER: usize = 8096;

pub fn default_socket_send_address() -> SocketAddr
{
    return SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
}

pub fn default_allowed_host() -> SocketAddr
{
    return SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 89)), 8900);
}

pub fn default_allowed_hosts() -> Vec<SocketAddr>
{
    return vec![default_allowed_host()];
}

pub fn default_clipboard() -> String
{
    return DEFAULT_CLIPBOARD.to_owned();
}
