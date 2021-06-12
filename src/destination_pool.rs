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
                if !all.contains_key(&group_id) {
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
                }

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

#[cfg(test)]
mod destinationpooltest
{
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn test_group_limit()
    {
        let pool = DestinationPool::new(2, 2, 4);
        let group_id1: GroupId = vec![1; 64].try_into().unwrap();
        let destination1: SocketAddr = "127.0.0.1:8001".parse().unwrap();
        pool.add_destination(group_id1.clone(), destination1);
        let group_id2: GroupId = vec![2; 64].try_into().unwrap();
        let destination2: SocketAddr = "127.0.0.1:8002".parse().unwrap();
        pool.add_destination(group_id2.clone(), destination2);

        let group_id3: GroupId = vec![3; 64].try_into().unwrap();
        let destination3: SocketAddr = "127.0.0.1:8003".parse().unwrap();
        pool.add_destination(group_id3.clone(), destination3);

        let destinations = pool.get_destinations(&group_id1);
        assert_eq!(vec![destination1], destinations);
        let destinations = pool.get_destinations(&group_id2);
        assert_eq!(vec![destination2], destinations);
        let destinations = pool.get_destinations(&group_id3);
        let expected: Vec<SocketAddr> = vec![];
        assert_eq!(expected, destinations);

        let group_unkown: GroupId = vec![0; 64].try_into().unwrap();
        let destinations = pool.get_destinations(&group_unkown);
        assert_eq!(expected, destinations);
    }

    #[test]
    fn test_socket_limit()
    {
        let pool = DestinationPool::new(1, 2, 1);
        let group_id: GroupId = vec![1; 64].try_into().unwrap();
        let destination1: SocketAddr = "127.0.0.1:8001".parse().unwrap();
        pool.add_destination(group_id.clone(), destination1);

        let destinations = pool.get_destinations(&group_id);
        assert_eq!(vec![destination1], destinations);

        let destination2: SocketAddr = "127.0.0.1:8002".parse().unwrap();
        pool.add_destination(group_id.clone(), destination2);

        let mut destinations = pool.get_destinations(&group_id);
        destinations.sort();
        assert_eq!(vec![destination1, destination2], destinations);

        let destination3: SocketAddr = "127.0.0.1:8003".parse().unwrap();
        pool.add_destination(group_id.clone(), destination3);

        let mut destinations = pool.get_destinations(&group_id);
        destinations.sort();
        assert_eq!(vec![destination1, destination2], destinations);
    }

    #[test]
    fn test_group_limit_per_ip()
    {
        let pool = DestinationPool::new(2, 2, 1);
        let group_id1: GroupId = vec![1; 64].try_into().unwrap();
        let destination1: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        pool.add_destination(group_id1.clone(), destination1);

        let group_id2: GroupId = vec![2; 64].try_into().unwrap();
        let destination2: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        pool.add_destination(group_id2.clone(), destination2);

        let destinations = pool.get_destinations(&group_id1);
        assert_eq!(vec![destination1], destinations);

        let destinations = pool.get_destinations(&group_id2);
        let expected: Vec<SocketAddr> = vec![];
        assert_eq!(expected, destinations);
    }

    #[test]
    fn test_cleanup()
    {
        let pool = DestinationPool::new(2, 2, 2);

        let group_id1: GroupId = vec![1; 64].try_into().unwrap();
        let destination1: SocketAddr = "127.0.0.1:8001".parse().unwrap();
        pool.add_destination(group_id1.clone(), destination1);
        let destination2: SocketAddr = "127.0.0.1:8002".parse().unwrap();
        pool.add_destination(group_id1.clone(), destination2);

        let group_id2: GroupId = vec![2; 64].try_into().unwrap();
        let destination3: SocketAddr = "127.0.0.1:8003".parse().unwrap();
        pool.add_destination(group_id2.clone(), destination3);

        let mut destinations = pool.get_destinations(&group_id1);
        destinations.sort();
        assert_eq!(vec![destination1, destination2], destinations);

        let destinations = pool.get_destinations(&group_id2);
        assert_eq!(vec![destination3], destinations);

        std::thread::sleep(std::time::Duration::from_secs(2));

        pool.cleanup(1);

        let destinations = pool.get_destinations(&group_id1);
        let expected: Vec<SocketAddr> = vec![];
        assert_eq!(expected, destinations);
    }
}
