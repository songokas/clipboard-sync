use chacha20poly1305::Key;
use clap::{Parser, ValueHint};
use indexmap::{indexset, IndexMap, IndexSet};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Error, ErrorKind};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::clipboards::{ClipboardSystem, Paths};
use crate::defaults::{
    get_default_hosts, BIND_ADDRESS, CLIPBOARD_NAME, DEFAULT_CLIPBOARD, KEY_SIZE, MAX_FILE_SIZE,
    MAX_RECEIVE_BUFFER, MESSAGE_VALID_FOR_STR_SECS, PACKAGE_NAME, RECEIVE_ONCE_WAIT_STR_SECS,
};
use crate::encryption::random_alphanumeric;
use crate::errors::CliError;
use crate::filesystem::write_file;
use crate::message::{
    AllowedHosts, DestinationHost, Group, GroupHosts, GroupName, Relay, SendGroup, ServerName,
};
use crate::protocol::Protocol;

#[derive(Default, Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CliConfig {
    #[arg(
        short,
        long,
        help = "set the level of logging verbosity",
        default_value = "info"
    )]
    pub verbosity: String,

    #[arg(short, long, help = "config file to load")]
    pub config: Option<PathBuf>,

    #[arg(short, long, help = "hosts to send and receive data from defaults to: 224.0.2.89:8900",  value_hint = ValueHint::Hostname)]
    pub allowed_host: Option<DestinationHost>,

    #[arg(short='l', long, help="address to listen on", default_value = BIND_ADDRESS)]
    pub bind_address: String,

    #[arg(short = 's', long, help = "address to use for sending data")]
    pub send_using_address: Option<String>,

    #[arg(short = 'g', long, help = "group to use", default_value = "default")]
    pub group: String,

    #[arg(short = 'p', long, help="clipboard type such as: clipboard, /path/to/file, /path/to/dir/, /dev/stdin", default_value = DEFAULT_CLIPBOARD)]
    pub clipboard: String,

    #[arg(short = 'k', long, help = "encryption key 32 chars long")]
    pub key: Option<String>,

    #[arg(short = 'u', long, help = "override ip visible to the receiver")]
    pub visible_ip: Option<String>,

    #[arg(long, help = "use protocol", default_value_t)]
    pub protocol: Protocol,

    #[arg(long, help = "path to private key")]
    pub private_key: Option<PathBuf>,

    #[arg(long, help = "path to certificate chain")]
    pub certificate_chain: Option<PathBuf>,

    #[arg(long, help = "path to a remote certificate directory")]
    pub remote_certificates: Option<PathBuf>,

    #[arg(
        long,
        help = "auto generate configuration/use configuration from the default path  ~/.config/clipboard-sync/config.yml"
    )]
    pub autogenerate: bool,

    #[arg(long, help = "send clipboard once and quit")]
    pub send_once: bool,

    #[arg(long, help = "receive clipboard once and quit")]
    pub receive_once: bool,

    #[arg(long, help="how many seconds to wait before quitting", value_parser = |s: &str| s.parse().map(Duration::from_secs), default_value = RECEIVE_ONCE_WAIT_STR_SECS)]
    pub receive_once_wait: Duration,

    #[arg(long, help = "do not send initial clipboard when application starts")]
    pub ignore_initial_clipboard: bool,

    #[arg(long, help = "send heartbeat messages", value_parser = |s: &str| s.parse().map(Duration::from_secs))]
    pub heartbeat: Option<Duration>,

    #[arg(long, help = "ntp server to use if validating messages with timestamp")]
    pub ntp_server: Option<String>,

    #[arg(long, help="how long the message is valid for in seconds", value_parser = |s: &str| s.parse().map(Duration::from_secs), default_value = MESSAGE_VALID_FOR_STR_SECS)]
    pub message_valid_for: Duration,

    #[arg(long, help="max data that can be received per connection", default_value_t = MAX_RECEIVE_BUFFER)]
    pub max_receive_buffer: usize,

    #[arg(long, help="max file size in bytes for sending/receiving files", default_value_t = MAX_FILE_SIZE)]
    pub max_file_size: usize,

    #[arg(
        long,
        help = "relay server hostname. add it to allowed host in order to use it example: clipsync.net:8900"
    )]
    pub relay_host: Option<String>,

    #[arg(
        long,
        help = "relay servers public key in base64 example: xskF0Ihe1s9gjIjw4VvL86FN8YkA3UHMjBzajRspwns="
    )]
    pub relay_public_key: Option<String>,

    #[arg(long, help = "do not verify server certificate")]
    pub danger_server_no_verify: bool,

    #[arg(long, help = "do not verify client certificate")]
    pub danger_client_no_verify: bool,

    #[arg(long, help = "send client certificate")]
    pub send_public_key: bool,

    #[arg(long, help = "receive client certificate")]
    pub receive_public_key: bool,

    #[arg(long, help = "path to application directory")]
    pub app_dir: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum SocketConfigAddress {
    Socket(SocketAddr),
    Multiple(IndexSet<SocketAddr>),
}

pub type BindAddresses = IndexMap<Protocol, IndexSet<SocketAddr>>;
pub type Groups = IndexMap<GroupName, Group>;
pub type SendGroups = IndexMap<GroupName, SendGroup>;
pub type GroupNames = IndexMap<GroupName, Duration>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileCertificates {
    pub private_key: PathBuf,
    pub certificate_chain: PathBuf,
    pub remote_certificates: Option<PathBuf>,
}

#[derive(Serialize, Debug, Clone)]
pub struct UserCertificates {
    pub private_key: String,
    pub certificate_chain: String,
    pub remote_certificates: Option<String>,
    pub subject: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserConfig {
    pub bind_addresses: Option<IndexMap<String, SocketConfigAddress>>,
    pub certificates: Option<FileCertificates>,

    pub send_using_address: Option<SocketConfigAddress>,
    pub visible_ip: Option<String>,

    pub groups: IndexMap<GroupName, ConfigGroup>,
    pub max_receive_buffer: Option<usize>,
    pub max_file_size: Option<usize>,
    pub receive_once_wait: Option<u64>,
    pub ntp_server: Option<String>,
    pub app_dir: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum ConfigAllowedHosts {
    Index(IndexSet<DestinationHost>),
    Map(IndexMap<DestinationHost, ServerName>),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigGroup {
    pub allowed_hosts: Option<ConfigAllowedHosts>,
    #[serde(default, with = "serde_key_str")]
    pub key: Option<Key>,
    pub visible_ip: Option<String>,
    pub send_using_address: Option<IndexSet<SocketAddr>>,
    pub clipboard: Option<String>,
    pub protocol: Option<Protocol>,
    pub heartbeat: Option<u64>,
    pub message_valid_for: Option<u16>,
    pub relay: Option<Relay>,
}

#[derive(Debug, Clone)]
pub struct FullConfig {
    pub bind_addresses: BindAddresses,
    pub groups: Groups,
    pub max_receive_buffer: usize,
    pub max_file_size: usize,
    pub receive_once_wait: Duration,
    pub send_clipboard_on_startup: bool,
    pub ntp_server: Option<String>,
    pub app_dir: Option<PathBuf>,
    pub tls_client_auth: bool,
}

impl FullConfig {
    // TODO
    #[allow(clippy::too_many_arguments)]
    pub fn from_protocol_groups(
        protocol: Protocol,
        bind_all: IndexSet<SocketAddr>,
        groups: Groups,
        max_receive_buffer: usize,
        max_file_size: usize,
        receive_once_wait: Duration,
        send_clipboard_on_startup: bool,
        ntp_server: Option<String>,
        app_dir: Option<PathBuf>,
        tls_client_auth: bool,
    ) -> Self {
        let mut bind_addresses: BindAddresses = IndexMap::new();
        bind_addresses.insert(protocol, bind_all);
        Self {
            bind_addresses,
            groups,
            max_receive_buffer,
            max_file_size,
            receive_once_wait,
            send_clipboard_on_startup,
            ntp_server,
            app_dir,
            tls_client_auth,
        }
    }

    // TODO
    #[allow(clippy::too_many_arguments)]
    pub fn from_config(
        bind_addresses: BindAddresses,
        groups: Groups,
        max_receive_buffer: usize,
        max_file_size: usize,
        receive_once_wait: Duration,
        send_clipboard_on_startup: bool,
        ntp_server: Option<String>,
        app_dir: Option<PathBuf>,
        tls_client_auth: bool,
    ) -> Self {
        Self {
            bind_addresses,
            groups,
            max_receive_buffer,
            max_file_size,
            receive_once_wait,
            send_clipboard_on_startup,
            ntp_server,
            app_dir,
            tls_client_auth,
        }
    }

    pub fn get_bind_addresses(&self) -> IndexSet<(Protocol, SocketAddr)> {
        self.bind_addresses
            .iter()
            .flat_map(|(p, v)| v.iter().map(move |s| (*p, *s)))
            .collect()
    }

    pub fn get_first_bind_address(&self) -> Option<(Protocol, SocketAddr)> {
        self.get_bind_addresses().into_iter().next()
    }

    pub fn get_filesystem_paths(&self) -> Paths {
        let mut paths = Paths::new();
        for (_, group) in self.groups.iter().filter(|(_, g)| {
            ClipboardSystem::from(g.clipboard.as_str()) == ClipboardSystem::Filesystem
        }) {
            paths
                .entry(PathBuf::from(&group.clipboard))
                .and_modify(|g| {
                    g.insert(group.name.clone());
                })
                .or_insert_with(|| indexset! { group.name.clone() });
        }
        paths
    }

    pub fn get_groups_by_clipboard(
        &self,
        clipboard_system: ClipboardSystem,
    ) -> IndexSet<GroupName> {
        self.groups
            .iter()
            .filter(|&(_, g)| (ClipboardSystem::from(g.clipboard.as_str()) == clipboard_system))
            .map(|(_, g)| g.name.clone())
            .collect()
    }

    pub fn get_groups_by_protocol(&self, protocol: Protocol) -> IndexMap<GroupName, SendGroup> {
        self.groups
            .iter()
            .filter(|(_, g)| protocol == g.protocol)
            .map(|(k, g)| (k.clone(), g.clone().into()))
            .collect()
    }

    pub fn get_groups_with_clipboard(&self) -> IndexMap<GroupName, (ClipboardSystem, String)> {
        self.groups
            .iter()
            .map(|(_, g)| {
                (
                    g.name.clone(),
                    (
                        ClipboardSystem::from(g.clipboard.as_str()),
                        g.clipboard.clone(),
                    ),
                )
            })
            .collect()
    }

    pub fn get_groups_with_protocol(&self) -> HashMap<GroupName, GroupHosts> {
        self.groups
            .iter()
            .map(|(_, g)| (g.name.clone(), g.clone().into()))
            .collect()
    }
}

pub fn load_default_certificates(
    app_dir: Option<PathBuf>,
    private_key: Option<&Path>,
    public_key: Option<&Path>,
    verify_dir: Option<&Path>,
) -> Result<FileCertificates, CliError> {
    let config_path = || {
        let dir = get_app_dir(app_dir.clone())?;
        if !dir.exists() {
            return Err(CliError::ArgumentError(
                format!("Unable to find configuration directory which usually located in ~/.config/{PACKAGE_NAME}")
            ));
        }
        Ok(dir)
    };

    let private_key = match private_key {
        Some(k) => k.to_owned(),
        None => config_path()?.join("cert.key"),
    };

    if !private_key.exists() {
        return Err(CliError::ArgumentError(format!(
            "Path {} to private key missing",
            private_key.to_string_lossy()
        )));
    }

    let server_certificate_chain = match public_key {
        Some(k) => k.to_owned(),
        None => config_path()?.join("cert.crt"),
    };

    if !server_certificate_chain.exists() {
        return Err(CliError::ArgumentError(format!(
            "Path {} to server certificate chain missing",
            server_certificate_chain.to_string_lossy()
        )));
    }

    let remote_certificates: Option<PathBuf> = match verify_dir {
        Some(k) => Some(k.into()),
        None => {
            let path = config_path()?.join("cert-verify");
            if !path.exists() {
                None
            } else {
                Some(path)
            }
        }
    };
    Ok(FileCertificates {
        private_key,
        certificate_chain: server_certificate_chain,
        remote_certificates,
    })
}

pub fn create_groups_from_config_file(
    file_path: &Path,
    cli_config: CliConfig,
    default_key: Key,
    cli_allowed_hosts: Option<AllowedHosts>,
    default_send_using_address: String,
    default_relay: Option<Relay>,
) -> Result<(FullConfig, Option<FileCertificates>), CliError> {
    info!("Loading from {} config", file_path.to_string_lossy());

    let yaml_file = File::open(file_path).map_err(|e| {
        CliError::ArgumentError(format!(
            "Unable to open yaml file path={} {e}",
            file_path.to_string_lossy()
        ))
    })?;
    let reader = BufReader::new(yaml_file);

    let user_config: UserConfig = serde_yaml::from_reader(reader).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("Unable to parse yaml file {e}"),
        )
    })?;

    let mut groups = IndexMap::new();

    for (group_name, group) in user_config.groups {
        let name = group_name.clone();
        let send_using_address = if let Some(sd) = &group.send_using_address {
            sd.clone()
        } else if let Some(sd) = &user_config.send_using_address {
            match sd {
                SocketConfigAddress::Socket(s) => indexset! {*s},
                SocketConfigAddress::Multiple(s) => s.clone(),
            }
        } else {
            default_send_using_address
                .split(',')
                .map(|v| {
                    v.parse::<SocketAddr>().map_err(|_| {
                        CliError::ArgumentError(format!(
                            "Invalid send-using-address provided {}",
                            v
                        ))
                    })
                })
                .collect::<Result<IndexSet<SocketAddr>, CliError>>()?
        };

        let protocol = group.protocol.unwrap_or(cli_config.protocol);

        let allowed_hosts: AllowedHosts = if let Some(sd) = group.allowed_hosts {
            match sd {
                ConfigAllowedHosts::Index(s) => s.into_iter().map(|v| (v, None)).collect(),
                ConfigAllowedHosts::Map(s) => s
                    .into_iter()
                    .map(|(k, v)| (k, (v.is_empty()).then_some(v)))
                    .collect(),
            }
        } else {
            cli_allowed_hosts
                .clone()
                .unwrap_or_else(|| get_default_hosts(protocol))
        };

        let visible_ip = if let Some(pub_ip) = &group.visible_ip {
            Some(pub_ip.clone())
        } else if let Some(pub_ip) = &user_config.visible_ip {
            Some(pub_ip.clone())
        } else {
            cli_config.visible_ip.clone()
        };

        let key = if let Some(k) = group.key {
            k
        } else {
            default_key
        };

        let relay = match &group.relay {
            Some(r) => Some(r.clone()),
            None => default_relay.clone(),
        };

        let heartbeat = if let Some(h) = group.heartbeat {
            if h > 0 {
                Duration::from_secs(h).into()
            } else {
                None
            }
        } else {
            cli_config
                .heartbeat
                .and_then(|s| (!s.is_zero()).then_some(s))
        };

        groups.insert(
            name.clone(),
            Group {
                name,
                allowed_hosts,
                key,
                visible_ip,
                send_using_address,
                clipboard: group.clipboard.clone().unwrap_or_else(|| {
                    if cli_config.clipboard == DEFAULT_CLIPBOARD {
                        CLIPBOARD_NAME.to_string()
                    } else {
                        cli_config.clipboard.clone()
                    }
                }),
                protocol,
                heartbeat,
                message_valid_for: group
                    .message_valid_for
                    .map(|v| Duration::from_secs(v as u64))
                    .or_else(|| {
                        (cli_config.message_valid_for > Duration::ZERO)
                            .then_some(cli_config.message_valid_for)
                    }),
                relay,
            },
        );
    }

    let receive_once_wait = user_config
        .receive_once_wait
        .map(Duration::from_secs)
        .unwrap_or(cli_config.receive_once_wait);
    let bind_addresses = create_bind_addresses(
        &user_config.bind_addresses,
        &cli_config.bind_address,
        cli_config.protocol,
    )?;

    let ntp_server = if let Some(ntp_server) = user_config.ntp_server {
        Some(ntp_server)
    } else {
        cli_config.ntp_server
    };

    let full_config = FullConfig::from_config(
        bind_addresses,
        groups,
        cli_config.max_receive_buffer,
        cli_config.max_file_size,
        receive_once_wait,
        !cli_config.ignore_initial_clipboard,
        ntp_server,
        user_config.app_dir.map(PathBuf::from),
        !cli_config.danger_client_no_verify,
    );
    Ok((full_config, user_config.certificates))
}

pub fn generate_config(config_dir: PathBuf) -> Result<(PathBuf, bool), CliError> {
    if !config_dir.exists() {
        std::fs::create_dir_all(&config_dir)?;
    }

    let path = config_dir.join("config.yml");

    if path.exists() {
        return Ok((path, false));
    }

    let str_contents = format!(
        "groups:\n   default:\n      key: {} \n",
        random_alphanumeric(KEY_SIZE)
    );
    write_file(&path, str_contents, 0o600)?;

    #[cfg(feature = "tls")]
    {
        let cert_path = config_dir.join("cert.crt");
        let private_key_path = config_dir.join("cert.key");
        if !cert_path.exists() || !private_key_path.exists() {
            let crate::config::UserCertificates {
                private_key,
                certificate_chain,
                ..
            } = crate::certificate::generate_pem_certificates(
                crate::certificate::random_certificate_subject(),
            );
            write_file(&cert_path, certificate_chain, 0o600)?;
            write_file(&private_key_path, private_key, 0o600)?;
        }
    }

    Ok((path, true))
}

pub fn get_app_dir(user_provided: Option<PathBuf>) -> Result<PathBuf, CliError> {
    if let Some(dir) = user_provided {
        return Ok(dir);
    }

    dirs::config_dir()
        .map(|p| p.join(PACKAGE_NAME))
        .ok_or_else(|| CliError::ArgumentError("Unable to retrieve configuration path".to_owned()))
}

fn create_bind_addresses(
    config_addresses: &Option<IndexMap<String, SocketConfigAddress>>,
    default_bind_address: &str,
    bind_default_protocol: Protocol,
) -> Result<BindAddresses, CliError> {
    let mut hash = IndexMap::new();
    if let Some(addresses) = config_addresses {
        for (protocol_str, sock_config_addr) in addresses {
            let protocol = match Protocol::from(Some(protocol_str)) {
                Ok(p) => p,
                Err(e) => {
                    warn!("{}. Skipping", e);
                    continue;
                }
            };

            let addresses = match sock_config_addr {
                SocketConfigAddress::Socket(s) => indexset! {*s},
                SocketConfigAddress::Multiple(s) => s.clone(),
            };

            hash.insert(protocol, addresses);
        }
    } else {
        let socket_addresses: IndexSet<SocketAddr> = default_bind_address
            .split(',')
            .map(|v| {
                v.parse::<SocketAddr>().map_err(|_| {
                    CliError::ArgumentError(format!("Invalid bind-address provided {}", v))
                })
            })
            .collect::<Result<IndexSet<SocketAddr>, CliError>>()?;
        hash.insert(bind_default_protocol, socket_addresses);
    }
    Ok(hash)
}

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub max_groups: u64,
    pub max_sockets: u64,
    pub keep_sockets_for: Duration,
    pub message_size: usize,
    pub private_key: [u8; KEY_SIZE],
    pub valid_for: Duration,
    pub max_per_ip: u64,
}

mod serde_key_str {
    use super::*;
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(key: &Option<Key>, serializer: S) -> Result<S::Ok, S::Error> {
        match key {
            Some(v) => serializer.serialize_str(&String::from_utf8_lossy(v)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Key>, D::Error> {
        let str_data: String = Deserialize::deserialize(deserializer)?;
        if str_data.len() != KEY_SIZE {
            return Err(de::Error::custom(format!(
                "Key size must be {} provided {} value {}",
                KEY_SIZE,
                str_data.len(),
                str_data
            )));
        }
        Ok(Some(*Key::from_slice(str_data.as_bytes())))
    }
}

#[cfg(test)]
mod configtest {
    use super::*;
    use indexmap::indexmap;
    #[test]
    fn test_load_groups() {
        let cli_config = CliConfig::default();
        let socket_addr = "127.0.0.1:8080";
        let mut default_allowed_hosts = IndexMap::new();
        default_allowed_hosts.insert(socket_addr.to_string(), None);
        let (full_config, user_certificates) = create_groups_from_config_file(
            Path::new("tests/config.sample.yaml"),
            cli_config,
            *Key::from_slice(b"23232323232323232323232323232323"),
            default_allowed_hosts.into(),
            "127.0.0.1:9088".to_string(),
            None,
        )
        .unwrap();

        assert!(user_certificates.is_some());

        let mut hash = IndexMap::new();
        hash.insert(
            Protocol::Basic,
            indexset! {"127.0.0.1:8910".parse::<SocketAddr>().unwrap()},
        );

        hash.insert(
            Protocol::Tcp,
            indexset! {"127.0.0.1:8911".parse::<SocketAddr>().unwrap()},
        );

        hash.insert(
            Protocol::Quic,
            indexset! {"127.0.0.1:8912".parse::<SocketAddr>().unwrap()},
        );
        assert_eq!(full_config.bind_addresses, hash);

        let group1 = &full_config.groups[0];
        assert_eq!(group1.name, "specific_hosts");
        assert_eq!(
            group1.send_using_address,
            indexset!["0.0.0.0:8901".parse::<SocketAddr>().unwrap()],
        );
        assert_eq!(group1.visible_ip, Some("ifconfig.co".to_owned()));

        let allowed_local = indexmap! {
            "192.168.0.153:8900".to_string() => None,
            "192.168.0.54:20034".to_string() => None
        };
        assert_eq!(group1.allowed_hosts, allowed_local);

        assert_eq!(group1.protocol, Protocol::Basic);

        let group2 = &full_config.groups[1];

        assert_eq!(group2.name, "local_network");
        assert_eq!(
            group2.send_using_address,
            indexset!["0.0.0.0:8901".parse::<SocketAddr>().unwrap()],
        );
        assert_eq!(group1.visible_ip, Some("ifconfig.co".to_owned()));

        let allowed_hosts = indexmap! {socket_addr.to_string() => None};
        assert_eq!(group2.allowed_hosts, allowed_hosts);

        let group3 = &full_config.groups[2];

        assert_eq!(group3.name, "external");
        assert_eq!(
            group3.send_using_address,
            indexset! {"0.0.0.0:9000".parse::<SocketAddr>().unwrap()}
        );
        assert_eq!(group3.visible_ip, Some("2.2.2.2".parse().unwrap()));

        let allowed_ext = indexmap! {"localhost:80".to_string() => None};
        assert_eq!(group3.allowed_hosts, allowed_ext);

        let group4 = &full_config.groups[5];
        let allowed_receive =
            indexmap! {"192.168.0.111:0".to_owned() => None, "192.168.0.112:0".to_owned() => None};
        assert_eq!(group4.allowed_hosts, allowed_receive);
    }

    #[test]
    fn test_generate_config() {
        let random_dir = "/tmp/_random_clipbboard_sync_test_generate_config";
        let (result, _) = generate_config(random_dir.parse().unwrap()).unwrap();
        assert!(result.ends_with("config.yml"));
        std::fs::remove_dir_all(result.parent().unwrap()).unwrap();
    }

    #[test]
    fn test_load_bad_config() {
        let cli_config = CliConfig::default();
        let full_config = create_groups_from_config_file(
            Path::new("tests/config.failure.yaml"),
            cli_config,
            *Key::from_slice(b"23232323232323232323232323232323"),
            Default::default(),
            "127.0.0.1:9088".to_string(),
            None,
        );

        assert!(full_config.is_err());
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct TestKey {
        #[serde(with = "serde_key_str")]
        pub key: Option<Key>,
    }

    #[test]
    fn test_key_serialize() {
        let key_data = "12345678123456781234567812345678";
        let key = Key::from_slice(key_data.as_bytes());
        let data = TestKey { key: Some(*key) };
        let result = bincode::serialize(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_key_deserialize() {
        let key_data = [
            32, 0, 0, 0, 0, 0, 0, 0, 49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55,
            56, 49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56,
        ];
        let result = bincode::deserialize::<TestKey>(&key_data);
        assert!(result.is_ok());

        let key_data = [
            32, 0, 0, 0, 0, 0, 0, 0, 49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55,
            56, 49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56, 56, 49, 50, 51, 52,
            53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56,
        ];
        let result = bincode::deserialize::<TestKey>(&key_data);
        assert!(result.is_ok());

        let key_data = [
            1, 0, 0, 0, 0, 0, 0, 0, 49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56,
            49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56,
        ];
        let result = bincode::deserialize::<TestKey>(&key_data);
        assert!(result.is_err());

        let key_data = [
            1, 0, 0, 0, 0, 0, 0, 0, 49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56,
        ];
        let result = bincode::deserialize::<TestKey>(&key_data);
        assert!(result.is_err());

        let key_data = [];
        let result = bincode::deserialize::<TestKey>(&key_data);
        assert!(result.is_err());
    }
}
