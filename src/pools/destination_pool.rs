use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::RwLock;
use std::time::Instant;

use crate::errors::RelayLimitError;
use crate::message::GroupId;

pub struct DestinationPool {
    addresses: RwLock<HashMap<GroupId, HashMap<SocketAddr, Instant>>>,
    ips: RwLock<HashMap<IpAddr, HashSet<GroupId>>>,
    max_sockets: usize,
    max_groups: usize,
    max_per_ip: usize,
}

impl DestinationPool {
    pub fn new(max_groups: usize, max_sockets: usize, max_per_ip: usize) -> Self {
        Self {
            addresses: RwLock::new(HashMap::new()),
            ips: RwLock::new(HashMap::new()),
            max_groups,
            max_sockets,
            max_per_ip,
        }
    }

    pub fn get_destinations(&self, group_id: &GroupId) -> Vec<SocketAddr> {
        match self.addresses.read() {
            Ok(h) => h
                .get(group_id)
                .map(|h| h.keys().cloned().collect())
                .unwrap_or_default(),
            Err(_) => vec![],
        }
    }

    pub fn add_destination(
        &self,
        group_id: GroupId,
        address: SocketAddr,
    ) -> Result<(bool, bool), RelayLimitError> {
        self.add_hash(group_id, address).and_then(|added| {
            if added {
                self.add_ip(group_id, address).map(|r| (added, r))
            } else {
                Ok((added, false))
            }
        })
    }

    pub fn cleanup(&self, oldest: Duration) -> (usize, usize) {
        let removed_addr = self.cleanup_hash(oldest);
        let removed_ips = self.cleanup_ips();
        (removed_addr, removed_ips)
    }

    fn cleanup_hash(&self, oldest: Duration) -> usize {
        let mut addrs = self.addresses.write().expect("Address lock");
        let current = addrs.len();
        addrs.retain(|_, v| {
            v.retain(|_, t| t.elapsed() < oldest);
            !v.is_empty()
        });
        current - addrs.len()
    }

    fn cleanup_ips(&self) -> usize {
        let mut ips = self.ips.write().expect("Ips lock");
        let addrs = self.addresses.read().expect("Address lock");
        let current = ips.len();
        ips.retain(|_, v| {
            v.retain(|group_id| addrs.contains_key(group_id));
            !v.is_empty()
        });

        current - ips.len()
    }

    fn add_hash(&self, group_id: GroupId, address: SocketAddr) -> Result<bool, RelayLimitError> {
        let ip_hash_limit = match self.ips.read() {
            Ok(t) => t.get(&address.ip()).map(|h| h.len()),
            Err(e) => {
                return Err(RelayLimitError::Lock(format!(
                    "Unable to obtain ip lock {}",
                    e
                )))
            }
        };

        match self.addresses.write() {
            Ok(mut all) => {
                if !all.contains_key(&group_id) {
                    if let Some(len) = ip_hash_limit {
                        if len >= self.max_per_ip {
                            return Err(RelayLimitError::Ips(self.max_per_ip));
                        }
                    }
                    if all.len() >= self.max_groups {
                        return Err(RelayLimitError::Groups(self.max_groups));
                    }

                    let mut h = HashMap::new();
                    h.insert(address, Instant::now());
                    all.insert(group_id, h);
                    Ok(true)
                } else {
                    all.entry(group_id).and_modify(|h| {
                        if h.len() < self.max_sockets {
                            h.insert(address, Instant::now());
                        }
                    });
                    Ok(false)
                }
            }
            Err(e) => Err(RelayLimitError::Lock(format!(
                "Unable to obtain hash lock {}",
                e
            ))),
        }
    }
    fn add_ip(&self, group_id: GroupId, address: SocketAddr) -> Result<bool, RelayLimitError> {
        match self.ips.write() {
            Ok(mut ip_list) => {
                ip_list
                    .entry(address.ip())
                    .and_modify(|v| {
                        v.insert(group_id);
                    })
                    .or_insert_with(|| {
                        let mut h = HashSet::new();
                        h.insert(group_id);
                        h
                    });
                Ok(true)
            }
            Err(e) => Err(RelayLimitError::Lock(format!(
                "Unable to write to ips {}",
                e
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::{convert::TryInto, time::Duration};

    use crate::encryption::random;

    #[test]
    fn test_group_limit() {
        let pool = DestinationPool::new(2, 2, 4);
        let group_id1: GroupId = vec![1; 64].try_into().unwrap();
        let destination1: SocketAddr = "127.0.0.1:8001".parse().unwrap();
        pool.add_destination(group_id1, destination1).unwrap();
        let group_id2: GroupId = vec![2; 64].try_into().unwrap();
        let destination2: SocketAddr = "127.0.0.1:8002".parse().unwrap();
        pool.add_destination(group_id2, destination2).unwrap();

        let group_id3: GroupId = vec![3; 64].try_into().unwrap();
        let destination3: SocketAddr = "127.0.0.1:8003".parse().unwrap();
        assert!(matches!(
            pool.add_destination(group_id3, destination3),
            Err(RelayLimitError::Groups(_))
        ));

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
    fn test_socket_limit() {
        let pool = DestinationPool::new(1, 2, 1);
        let group_id: GroupId = vec![1; 64].try_into().unwrap();
        let destination1: SocketAddr = "127.0.0.1:8001".parse().unwrap();
        pool.add_destination(group_id, destination1).unwrap();

        let destinations = pool.get_destinations(&group_id);
        assert_eq!(vec![destination1], destinations);

        let destination2: SocketAddr = "127.0.0.1:8002".parse().unwrap();
        pool.add_destination(group_id, destination2).unwrap();

        let mut destinations = pool.get_destinations(&group_id);
        destinations.sort();
        assert_eq!(vec![destination1, destination2], destinations);

        let destination3: SocketAddr = "127.0.0.1:8003".parse().unwrap();
        pool.add_destination(group_id, destination3).unwrap();

        let mut destinations = pool.get_destinations(&group_id);
        destinations.sort();
        assert_eq!(vec![destination1, destination2], destinations);
    }

    #[test]
    fn test_group_limit_per_ip() {
        let pool = DestinationPool::new(2, 2, 1);
        let group_id1: GroupId = vec![1; 64].try_into().unwrap();
        let destination1: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        pool.add_destination(group_id1, destination1).unwrap();

        let group_id2: GroupId = vec![2; 64].try_into().unwrap();
        let destination2: SocketAddr = "127.0.0.1:9000".parse().unwrap();

        assert!(matches!(
            pool.add_destination(group_id2, destination2),
            Err(RelayLimitError::Ips(_))
        ));

        let destinations = pool.get_destinations(&group_id1);
        assert_eq!(vec![destination1], destinations);

        let destinations = pool.get_destinations(&group_id2);
        let expected: Vec<SocketAddr> = vec![];
        assert_eq!(expected, destinations);
    }

    #[test]
    fn test_cleanup() {
        let pool = DestinationPool::new(2, 2, 2);

        let group_id1: GroupId = vec![1; 64].try_into().unwrap();
        let destination1: SocketAddr = "127.0.0.1:8001".parse().unwrap();
        pool.add_destination(group_id1, destination1).unwrap();
        let destination2: SocketAddr = "127.0.0.1:8002".parse().unwrap();
        pool.add_destination(group_id1, destination2).unwrap();

        let group_id2: GroupId = vec![2; 64].try_into().unwrap();
        let destination3: SocketAddr = "127.0.0.1:8003".parse().unwrap();
        pool.add_destination(group_id2, destination3).unwrap();

        let mut destinations = pool.get_destinations(&group_id1);
        destinations.sort();
        assert_eq!(vec![destination1, destination2], destinations);

        let destinations = pool.get_destinations(&group_id2);
        assert_eq!(vec![destination3], destinations);

        std::thread::sleep(std::time::Duration::from_secs(2));

        let (r1, r2) = pool.cleanup(Duration::from_secs(1));
        assert_eq!(2, r1);
        assert_eq!(1, r2);

        let destinations = pool.get_destinations(&group_id1);
        let expected: Vec<SocketAddr> = vec![];
        assert_eq!(expected, destinations);
    }

    #[test]
    fn test_thead_cleanup() {
        let pool = Arc::new(DestinationPool::new(10000, 100, 10));
        let pool1 = pool.clone();
        let pool2 = pool.clone();
        let t1 = thread::spawn(move || {
            let mut i = 30000;
            while i > 0 {
                let g: GroupId = random(64).try_into().unwrap();
                let s: SocketAddr = format!("127.0.0.1:{}", i).parse().unwrap();
                pool1.add_destination(g, s).unwrap();
                pool1.get_destinations(&g);
                i -= 1;
            }
        });
        let t2 = thread::spawn(move || {
            let mut i = 300;
            let mut r = (0, 0);
            while i > 0 {
                r = pool2.cleanup(Duration::from_secs(1));
                thread::sleep(Duration::from_millis(10));
                i -= 1;
            }
            r
        });

        let _res1 = t1.join();
        let res2 = t2.join().unwrap();

        assert_eq!(res2.0, 0);
        assert_eq!(res2.1, 0);
    }
}
