use log::{error, info};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Error, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::collections::HashMap;

use crate::errors::CliError;
use crate::message::{serde_default_socket, Group};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FullConfig
{
    pub bind_address: SocketAddr,
    pub send_using_address: Option<SocketAddr>,
    pub public_ip: Option<IpAddr>,
    // @TODO this should be Vec<Group> find a better way to deal with serde
    groups: HashMap<String, Group>,
}

impl FullConfig
{
    pub fn from_groups(
        bind_address: SocketAddr,
        send_using_address: SocketAddr,
        public_ip: Option<IpAddr>,
        groups: Vec<Group>,
    ) -> Self
    {
        return FullConfig {
            bind_address,
            send_using_address: Some(send_using_address),
            public_ip: public_ip,
            groups: to_hash_map(&groups),
        };
    }

    pub fn groups(&self) -> Vec<Group> {
        return self.groups
            .iter()
            .map(|(_, v)| {
                v.clone()
            })
            .collect();
    }
}

pub fn load_groups(
    file_path: &str,
    default_host_address: SocketAddr,
) -> Result<FullConfig, CliError>
{
    info!("Loading from {} config", file_path);
    let yaml_file = File::open(&file_path)
        .map_err(|err| error!("Error while opening: {:?}", err))
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Unable to open yaml file"))?;
    let reader = BufReader::new(yaml_file);

    let mut full_config: FullConfig = serde_yaml::from_reader(reader)
        .map_err(|err| { error!("Error while parsing: {:?}", err); })
        .map_err(|_| Error::new(ErrorKind::InvalidData, format!("Unable to parse yaml file")))?;

    for (key, group) in full_config.groups.iter_mut() {
        group.name = key.clone();
        if let Some(sd) = full_config.send_using_address {
            if group.send_using_address == serde_default_socket() {
                group.send_using_address = sd;
            }
        }
        if group.allowed_hosts.len() == 0 {
            group.allowed_hosts.push(default_host_address);
        }
        if let Some(pub_ip) = full_config.public_ip {
            if group.public_ip.is_none() {
                group.public_ip = Some(pub_ip);
            }
        }
    }
    return Ok(full_config.clone());
}

fn to_hash_map(groups: &[Group]) -> HashMap<String, Group>
{
    let mut table = HashMap::new();
    for group in groups {
        table.insert(group.name.clone(), group.clone());
    }
    return table;
}