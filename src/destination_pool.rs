use crate::message::GroupId;
use log::error;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::RwLock;
use std::time::Instant;

pub struct DestinationPool
{
    addresses: RwLock<HashMap<GroupId, HashMap<SocketAddr, Instant>>>,
    ips: RwLock<HashMap<IpAddr, HashSet<GroupId>>>,
    max_sockets: usize,
    max_groups: usize,
    max_per_ip: usize,
}

impl DestinationPool
{
    pub fn new(max_groups: usize, max_sockets: usize, max_per_ip: usize) -> Self
    {
        return Self {
            addresses: RwLock::new(HashMap::new()),
            ips: RwLock::new(HashMap::new()),
            max_groups,
            max_sockets,
            max_per_ip,
        };
    }

    pub fn get_destinations(&self, group_id: &GroupId) -> Vec<SocketAddr>
    {
        match self.addresses.read() {
            Ok(h) => h
                .get(group_id)
                .map(|h| h.keys().cloned().collect())
                .unwrap_or(vec![]),
            Err(_) => vec![],
        }
    }

    pub fn add_destination(&self, group_id: GroupId, address: SocketAddr)
    {
        match self.addresses.write() {
            Ok(mut all) => {
                if all.len() >= self.max_groups {
                    return;
                }

                let result = match self.ips.read() {
                    Ok(t) => t.get(&address.ip()).map(|h| h.len()),
                    Err(_) => None,
                };

                match result {
                    Some(len) if len >= self.max_per_ip => return,
                    _ => (),
                };

                all.entry(group_id.clone())
                    .and_modify(|h| {
                        if h.len() < self.max_sockets {
                            h.insert(address, Instant::now());
                        }
                    })
                    .or_insert_with(|| {
                        let mut h = HashMap::new();

                        match self.ips.write() {
                            Ok(mut ip_list) => {
                                ip_list
                                    .entry(address.ip())
                                    .and_modify(|v| {
                                        v.insert(group_id.clone());
                                    })
                                    .or_insert_with(|| {
                                        let mut h = HashSet::new();
                                        h.insert(group_id);
                                        return h;
                                    });
                                h.insert(address, Instant::now());
                            }
                            Err(_) => (),
                        };
                        return h;
                    });
            }
            Err(e) => {
                error!("Failed to obtain write lock {}", e);
            }
        }
    }

    pub fn cleanup(&self, oldest: u64)
    {
        match self.addresses.write() {
            Ok(mut hash) => {
                hash.retain(|_, v| {
                    v.retain(|_, t| t.elapsed().as_secs() < oldest);
                    v.len() > 0
                });
            }
            Err(e) => {
                error!("Failed to obtain write lock {}", e);
            }
        };

        match self.ips.write() {
            Ok(mut ips) => match self.addresses.read() {
                Ok(addrs) => {
                    ips.retain(|_, v| {
                        v.retain(|group_id| addrs.contains_key(group_id));
                        v.len() > 0
                    });
                }
                _ => (),
            },
            _ => (),
        };
    }
}
