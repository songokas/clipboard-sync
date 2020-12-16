use log::{error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Error, ErrorKind};
use std::net::SocketAddr;

use crate::defaults::{default_allowed_hosts, default_socket_send_address};
use crate::errors::CliError;
use crate::message::Group;

#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Certificates
{
    pub private_key: String,
    pub public_key: String,
    pub verify_dir: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FullConfig
{
    pub bind_address: SocketAddr,

    pub send_using_address: Option<SocketAddr>,
    pub public_ip: Option<String>,
    pub certificates: Option<Certificates>,

    groups: HashMap<String, Group>,
}

impl FullConfig
{
    pub fn from_groups(
        bind_address: SocketAddr,
        send_using_address: SocketAddr,
        public_ip: Option<String>,
        groups: Vec<Group>,
    ) -> Self
    {
        return FullConfig {
            bind_address,
            send_using_address: Some(send_using_address),
            public_ip: public_ip,
            groups: to_hash_map(&groups),
            certificates: None,
        };
    }

    pub fn groups(&self) -> Vec<Group>
    {
        return self.groups.iter().map(|(_, v)| v.clone()).collect();
    }
}

pub fn load_default_certificates(
    private_key: Option<&str>,
    public_key: Option<&str>,
    verify_dir: Option<&str>,
) -> Result<Certificates, CliError>
{
    let config_path = || {
        dirs::config_dir()
            .map(|p| p.join("clipboard-sync"))
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
        Some(k) => Some(k.to_owned()),
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

pub fn load_groups(file_path: &str, default_host_address: &str) -> Result<FullConfig, CliError>
{
    info!("Loading from {} config", file_path);

    let yaml_file = File::open(&file_path)
        .map_err(|err| error!("Error while opening: {:?}", err))
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Unable to open yaml file"))?;
    let reader = BufReader::new(yaml_file);

    let mut full_config: FullConfig = serde_yaml::from_reader(reader)
        .map_err(|err| {
            error!("Error while parsing: {:?}", err);
        })
        .map_err(|_| Error::new(ErrorKind::InvalidData, format!("Unable to parse yaml file")))?;

    for (key, group) in full_config.groups.iter_mut() {
        group.name = key.clone();
        if let Some(sd) = full_config.send_using_address {
            if group.send_using_address == default_socket_send_address() {
                group.send_using_address = sd;
            }
        }
        if group.allowed_hosts.len() == 0 || group.allowed_hosts == default_allowed_hosts() {
            group.allowed_hosts = vec![default_host_address.to_owned()];
        }
        if let Some(pub_ip) = full_config.public_ip.clone() {
            if group.public_ip.is_none() {
                group.public_ip = Some(pub_ip);
            }
        }
    }
    return Ok(full_config);
}

fn to_hash_map(groups: &[Group]) -> HashMap<String, Group>
{
    let mut table = HashMap::new();
    for group in groups {
        table.insert(group.name.clone(), group.clone());
    }
    return table;
}

#[cfg(test)]
mod configtest
{
    use super::*;

    #[test]
    fn test_load_groups()
    {
        let socket_addr = "127.0.0.1:8080";
        let full_config = load_groups("config.sample.yaml", socket_addr).unwrap();
        assert_eq!(
            full_config.bind_address,
            "0.0.0.0:8900".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            full_config.send_using_address,
            Some("0.0.0.0:8901".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(full_config.public_ip, Some("ifconfig.co".to_owned()));

        assert_eq!(
            full_config.certificates,
            Some(Certificates {
                private_key: "tests/cert.key".to_owned(),
                public_key: "tests/cert.crt".to_owned(),
                verify_dir: Some("tests/cert-verify".to_owned()),
            })
        );

        let group1 = full_config.groups.get("specific_hosts").unwrap();

        assert_eq!(group1.name, "specific_hosts");
        assert_eq!(
            group1.send_using_address,
            full_config.send_using_address.unwrap()
        );
        assert_eq!(group1.public_ip, full_config.public_ip);
        let allowed_local = vec!["192.168.0.153:8900", "192.168.0.54:20034"];
        assert_eq!(group1.allowed_hosts, allowed_local);

        let group2 = full_config.groups.get("local_network").unwrap();

        assert_eq!(group2.name, "local_network");
        assert_eq!(
            group2.send_using_address,
            full_config.send_using_address.unwrap()
        );
        assert_eq!(group2.public_ip, full_config.public_ip);

        let allowed_hosts = vec![socket_addr];
        assert_eq!(group2.allowed_hosts, allowed_hosts);

        let group3 = full_config.groups.get("external").unwrap();

        assert_eq!(group3.name, "external");
        assert_eq!(
            group3.send_using_address,
            "0.0.0.0:9000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(group3.public_ip, Some("2.2.2.2".to_owned()));

        let allowed_ext = vec!["external.net:80"];
        assert_eq!(group3.allowed_hosts, allowed_ext);

        let group4 = full_config.groups.get("receive_only_dir").unwrap();
        let allowed_receive = vec!["192.168.0.111:0", "192.168.0.112:0"];
        assert_eq!(group4.allowed_hosts, allowed_receive);
    }
}
