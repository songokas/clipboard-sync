pub const BIND_ADDRESS: &str = "0.0.0.0:8900";
// pub const BIND_ADDRESS_IPV6: &str = "0.0.0.0:8900,[::]:8900";
// pub const BIND_ADDRESS_IPV6_ONLY: &str = "[::]:8900";
pub const SEND_ADDRESS: &str = "0.0.0.0:0";
pub const SEND_ADDRESS_IPV6: &str = "0.0.0.0:0,[::]:0";
pub const DEFAULT_ALLOWED_HOST: &str = "224.0.0.89:8900";
// pub const DEFAULT_ALLOWED_HOST_IPV6: &str = "[ff02:1000:1000:dada::1%3]:8900";
pub const DEFAULT_GROUP: &str = "default";
pub const CLIPBOARD_NAME: &str = "clipboard";
pub const DEFAULT_CLIPBOARD: &str = CLIPBOARD_NAME;
pub const DEFAULT_PROTOCOL: &str = "basic";
pub const PACKAGE_NAME: &str = "clipboard-sync";
pub const MAX_CHANNEL: usize = 100;
pub const KEY_SIZE: usize = 32;
pub const MAX_FILE_SIZE: usize = 22 * 1024 * 1024;
pub const MAX_RECEIVE_BUFFER: usize = 50 * 1024 * 1024;
pub const MAX_UDP_PAYLOAD: usize = 63535;
pub const MAX_UDP_BUFFER: usize = MAX_UDP_PAYLOAD + 500;

pub const MAX_PACKET: usize = 512;
pub const MAX_DATAGRAM_SIZE: usize = 1350;
pub const QUIC_STREAM: u8 = 0;
pub const CONNECTION_TIMEOUT: u64 = 2000;
pub const DATA_TIMEOUT: u64 = 5000;
pub const RECEIVE_ONCE_WAIT: u64 = 45; //seconds
pub const MAX_ENCRYPTION_HEADER_SIZE: u16 = 200; // encryption header size

pub const NTP_SERVER: &str = "0.pool.ntp.org:123";
pub const MESSAGE_VALID_TIME: u16 = 300;

pub fn default_clipboard() -> String
{
    return DEFAULT_CLIPBOARD.to_owned();
}
