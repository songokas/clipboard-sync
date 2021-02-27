use indexmap::IndexMap;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::{BufReader, Error, ErrorKind};
use std::net::SocketAddr;
use std::path::PathBuf;
use chacha20poly1305::Key;

use crate::defaults::{
    default_socket_send_address, DEFAULT_CLIPBOARD, KEY_SIZE, MAX_RECEIVE_BUFFER,
    PACKAGE_NAME, RECEIVE_ONCE_WAIT,
};
use crate::encryption::random_alphanumeric;
use crate::errors::CliError;
use crate::filesystem::write_file;
use crate::message::{ConfigGroup, Group};
use crate::socket::Protocol;

#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct Certificates
{
    pub private_key: String,
    pub public_key: String,
    pub verify_dir: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserConfig
{
    pub bind_addresses: Option<IndexMap<String, SocketAddr>>,
    pub send_using_address: Option<SocketAddr>,
    pub visible_ip: Option<String>,
    pub certificates: Option<Certificates>,
    pub max_receive_buffer: Option<usize>,
    pub receive_once_wait: Option<u64>,
    pub groups: IndexMap<String, ConfigGroup>,
}

#[derive(Debug, Clone)]
pub struct FullConfig
{
    pub bind_addresses: IndexMap<Protocol, SocketAddr>,
    pub groups: Vec<Group>,
    pub max_receive_buffer: usize,
    pub receive_once_wait: u64,
    pub send_clipboard_on_startup: bool,
}

impl FullConfig
{
    pub fn from_protocol_groups(
        protocol: Protocol,
        bind_address: SocketAddr,
        groups: Vec<Group>,
        max_receive_buffer: usize,
        receive_once_wait: u64,
        send_clipboard_on_startup: bool,
    ) -> Self
    {
        let mut bind_addresses: IndexMap<Protocol, SocketAddr> = IndexMap::new();
        bind_addresses.insert(protocol, bind_address);
        return FullConfig {
            bind_addresses,
            groups,
            max_receive_buffer,
            receive_once_wait,
            send_clipboard_on_startup,
        };
    }

    pub fn from_config(
        bind_addresses: IndexMap<Protocol, SocketAddr>,
        groups: Vec<Group>,
        max_receive_buffer: usize,
        receive_once_wait: u64,
        send_clipboard_on_startup: bool,
    ) -> Self
    {
        return FullConfig {
            bind_addresses,
            groups,
            max_receive_buffer,
            receive_once_wait,
            send_clipboard_on_startup,
        };
    }

    pub fn get_bind_address(&self, protocol: &Protocol) -> Option<&SocketAddr>
    {
        return self.bind_addresses.get(protocol);
    }

    pub fn get_first_bind_address(&self) -> Option<(&Protocol, &SocketAddr)>
    {
        return self.bind_addresses.iter().next();
    }
}

#[allow(dead_code)]
pub fn load_default_certificates(
    private_key: Option<&str>,
    public_key: Option<&str>,
    verify_dir: Option<&str>,
) -> Result<Certificates, CliError>
{
    let config_path = || {
        dirs::config_dir()
            .map(|p| p.join(PACKAGE_NAME))
            .ok_or_else(|| {
                CliError::InvalidKey(
                    "Quic unable to find config path with keys CONFIG_PATH is usually ~/.config"
                        .to_owned(),
                )
            })
    };

    let key_str: String = match private_key {
        Some(k) => k.to_owned(),
        None => {
            let path = config_path()?.join("cert.key");
            path.to_string_lossy().to_string()
        }
    };

    let crt_str: String = match public_key {
        Some(k) => k.to_owned(),
        None => {
            let path = config_path()?.join("cert.crt");
            path.to_string_lossy().to_string()
        }
    };

    let verify_str: Option<String> = match verify_dir {
        Some(k) => Some(k.into()),
        None => {
            let path = config_path()?.join("cert-verify");
            if !path.exists() {
                None
            } else {
                Some(path.to_string_lossy().to_string())
            }
        }
    };

    return Ok(Certificates {
        private_key: key_str,
        public_key: crt_str,
        verify_dir: verify_str,
    });
}

pub fn load_groups(
    file_path: &str,
    default_allowed_host_address: &str,
    default_bind_address: &str,
    default_protocol: Option<&str>,
    load_cli_certs: impl Fn() -> Result<Certificates, CliError>,
    send_clipboard_on_startup: bool,
    default_visible_ip: Option<String>,
    default_key: String,
) -> Result<FullConfig, CliError>
{
    info!("Loading from {} config", file_path);

    let yaml_file = File::open(&file_path)
        .map_err(|err| error!("Error while opening: {:?}", err))
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Unable to open yaml file"))?;
    let reader = BufReader::new(yaml_file);

    let user_config: UserConfig = serde_yaml::from_reader(reader)
        .map_err(|err| {
            error!("Error while parsing: {:?}", err);
        })
        .map_err(|_| Error::new(ErrorKind::InvalidData, format!("Unable to parse yaml file")))?;

    let mut groups = vec![];

    let load_certs = || -> Result<Certificates, CliError> {
        if let Some(c) = &user_config.certificates {
            return Ok(c.clone());
        }

        if let Ok(c) = load_cli_certs() {
            return Ok(c);
        }
        return Err(CliError::InvalidKey(format!("Failed to load certificate")));
    };

    for (key, group) in &user_config.groups {
        let name = key.clone();
        let send_using_address = if let Some(sd) = &group.send_using_address {
            sd.clone()
        } else if let Some(sd) = &user_config.send_using_address {
            sd.clone()
        } else {
            default_socket_send_address()
        };

        let allowed_hosts = if let Some(sd) = &group.allowed_hosts {
            sd.clone()
        } else {
            vec![String::from(default_allowed_host_address)]
        };

        let visible_ip = if let Some(pub_ip) = &group.visible_ip {
            Some(pub_ip.clone())
        } else if let Some(pub_ip) = &user_config.visible_ip {
            Some(pub_ip.clone())
        } else {
            default_visible_ip.clone()
        };

        let c_proto = group.protocol.as_deref().or(default_protocol);

        let protocol = Protocol::from(c_proto, load_certs)?;

        let key_data = if let Some(k) = group.key {
            k.clone()
        } else {
            if default_key.len() != KEY_SIZE {
                return Err(CliError::InvalidKey(format!("No key provided"))); 
            }
            Key::from_slice(default_key.as_bytes()).clone()
        };

        groups.push(Group {
            name,
            allowed_hosts,
            key: key_data,
            visible_ip,
            send_using_address,
            clipboard: group
                .clipboard
                .clone()
                .unwrap_or(String::from(DEFAULT_CLIPBOARD)),
            protocol,
        });
    }

    let max_receive_buffer = user_config.max_receive_buffer.unwrap_or(MAX_RECEIVE_BUFFER);
    let receive_once_wait = user_config.receive_once_wait.unwrap_or(RECEIVE_ONCE_WAIT);
    let bind_default_protocol = Protocol::from(default_protocol, load_certs)?;
    let bind_addresses = create_bind_addresses(&user_config.bind_addresses, default_bind_address, load_certs, bind_default_protocol)?;
    let full_config = FullConfig::from_config(
        bind_addresses,
        groups,
        max_receive_buffer,
        receive_once_wait,
        send_clipboard_on_startup,
    );
    return Ok(full_config);
}

pub fn generate_config(dir_name: &str) -> Result<PathBuf, CliError>
{
    let config_dir = dirs::config_dir()
        .map(|p| p.join(dir_name))
        .ok_or_else(|| {
            CliError::ArgumentError(
                "Unable to generate configuration. Use --config option instead".to_owned(),
            )
        })?;

    if !config_dir.exists() {
        fs::create_dir_all(config_dir.clone())?;
    }

    let path = config_dir.join("config.yml");

    if path.exists() {
        return Ok(path);
    }

    let str_contents = format!(
        "groups:\n   default:\n      key: {} \n",
        random_alphanumeric(KEY_SIZE)
    );
    write_file(&path, str_contents.as_bytes(), 0o600)?;
    return Ok(path);
}

fn create_bind_addresses(
    config_addresses: &Option<IndexMap<String, SocketAddr>>,
    default_bind_address: &str,
    load_certs: impl Fn() -> Result<Certificates, CliError> + Copy,
    bind_default_protocol: Protocol,
) -> Result<IndexMap<Protocol, SocketAddr>, CliError>
{
    let mut hash = IndexMap::new();
    if let Some(addresses) = config_addresses {
        for (protocol_str, sock_addr) in addresses {
            let protocol = match Protocol::from(Some(protocol_str), load_certs) {
                Ok(p) => p,
                Err(e) => {
                    warn!("{:?}. Skipping", e);
                    continue;
                }
            };
            hash.insert(protocol, sock_addr.clone());
        }
    } else {
        let socket: SocketAddr = default_bind_address
            .parse()
            .expect("Failed parsing default bind address");
        hash.insert(bind_default_protocol, socket);
    }

    return Ok(hash);
}

#[cfg(test)]
mod configtest
{
    use super::*;

    #[test]
    fn test_load_groups()
    {
        #[cfg(feature = "quic")]
        let certificates = Certificates {
            private_key: "tests/cert.key".to_owned(),
            public_key: "tests/cert.crt".to_owned(),
            verify_dir: Some("tests/cert-verify".to_owned()),
        };

        let socket_addr = "127.0.0.1:8080";
        let full_config = load_groups(
            "tests/config.sample.yaml",
            socket_addr,
            "127.0.0.1:9088",
            None,
            || Err(CliError::InvalidKey("test no key".to_owned())),
            false,
            None,
            "".to_owned(),
        )
        .unwrap();

        let mut hash = IndexMap::new();
        hash.insert(
            Protocol::Basic,
            "127.0.0.1:8910".parse::<SocketAddr>().unwrap(),
        );
        hash.insert(
            Protocol::Frames,
            "127.0.0.1:9010".parse::<SocketAddr>().unwrap(),
        );
        #[cfg(feature = "quic")]
        hash.insert(
            Protocol::Quic(certificates),
            "127.0.0.1:9110".parse::<SocketAddr>().unwrap(),
        );
        assert_eq!(full_config.bind_addresses, hash);

        let group1 = &full_config.groups[0];
        assert_eq!(group1.name, "specific_hosts");
        assert_eq!(
            group1.send_using_address,
            "127.0.0.1:8901".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(group1.visible_ip, Some("ifconfig.co".to_owned()));

        let allowed_local = vec!["192.168.0.153:8900", "192.168.0.54:20034"];
        assert_eq!(group1.allowed_hosts, allowed_local);

        assert_eq!(group1.protocol, Protocol::Basic);

        let group2 = &full_config.groups[1];

        assert_eq!(group2.name, "local_network");
        assert_eq!(
            group2.send_using_address,
            "127.0.0.1:8901".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(group1.visible_ip, Some("ifconfig.co".to_owned()));

        let allowed_hosts = vec![socket_addr];
        assert_eq!(group2.allowed_hosts, allowed_hosts);

        assert_eq!(group2.protocol, Protocol::Frames);

        let group3 = &full_config.groups[2];

        assert_eq!(group3.name, "external");
        assert_eq!(
            group3.send_using_address,
            "127.0.0.1:9000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(group3.visible_ip, Some("2.2.2.2".to_owned()));

        let allowed_ext = vec!["external.net:80"];
        assert_eq!(group3.allowed_hosts, allowed_ext);

        let group4 = &full_config.groups[5];
        let allowed_receive = vec!["192.168.0.111:0", "192.168.0.112:0"];
        assert_eq!(group4.allowed_hosts, allowed_receive);
    }

    #[test]
    fn test_generate_config()
    {
        let random_dir = "_random_clipbboard_sync_test_dir";
        let result = generate_config(random_dir).unwrap();
        assert!(result.ends_with("config.yml"));
        fs::remove_file(result.clone()).unwrap();
        fs::remove_dir(result.parent().unwrap()).unwrap();
    }

    #[test]
    fn test_load_bad_config()
    {
        let socket_addr = "127.0.0.1:8080";
        let full_config = load_groups(
            "tests/config.failure.yaml",
            socket_addr,
            "127.0.0.1:9088",
            None,
            || Err(CliError::InvalidKey("test no key".to_owned())),
            false,
            None,
            "".to_owned(),
        );

        match full_config {
            Ok(_) => assert!(false, "Error expected"),
            Err(_) => assert!(true),
        };
    }
}
