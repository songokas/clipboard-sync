use core::{future::Future, net::SocketAddr, time::Duration};
use std::{sync::Arc, time::Instant};

use indexmap::IndexMap;
use log::debug;

use crate::errors::ConnectionError;

pub enum SocketState<C, N> {
    Connected(C),
    NotConnected(Option<N>),
}

pub struct SocketData<T> {
    pub socket: Arc<T>,
    pub bound_addr: SocketAddr,
    pub new: bool,
    pub last_used: Instant,
}

#[derive(Default)]
pub struct SocketPool<T> {
    sockets: IndexMap<(SocketAddr, SocketAddr), SocketData<T>>,
}

impl<T> SocketPool<T> {
    pub fn new() -> Self {
        Self {
            sockets: IndexMap::new(),
        }
    }

    pub async fn obtain<F1, F2>(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        create_socket: impl Fn(SocketAddr, SocketAddr) -> F1,
        is_disconnected: impl Fn(Arc<T>) -> F2,
    ) -> Result<(Arc<T>, SocketAddr), ConnectionError>
    where
        F1: Future<Output = Result<(T, SocketAddr), ConnectionError>>,
        F2: Future<Output = bool>,
    {
        if let Some(s) = self.get(local_addr, remote_addr) {
            if is_disconnected(s.0.clone()).await {
                debug!("Disconnected local_addr={local_addr} remote_addr={remote_addr}");
                drop(s);
                self.remove(local_addr, remote_addr);
            } else {
                return Ok(s);
            }
        }

        let (socket, bound_addr) = create_socket(local_addr, remote_addr).await?;
        let socket = Arc::new(socket);
        // do not keep short lived sockets
        if local_addr.port() != 0 {
            self.insert(bound_addr, remote_addr, socket.clone());
        }
        Ok((socket, bound_addr))
    }

    pub fn insert(&mut self, bound_addr: SocketAddr, remote_addr: SocketAddr, socket: Arc<T>) {
        self.sockets.insert(
            (bound_addr, remote_addr),
            SocketData {
                socket,
                bound_addr,
                last_used: Instant::now(),
                new: true,
            },
        );
    }

    pub fn get_new_by_local_addr(
        &mut self,
        local_addr: SocketAddr,
    ) -> Option<(Arc<T>, SocketAddr)> {
        let (stream_data, remote_addr) = self
            .sockets
            .iter_mut()
            .find(|((l, _), s)| l == &local_addr && s.new)
            .map(|((_, r), s)| (s, r))?;
        stream_data.new = false;
        Some((stream_data.socket.clone(), *remote_addr))
    }

    pub fn get(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<(Arc<T>, SocketAddr)> {
        let stream_data = self.sockets.get(&(local_addr, remote_addr))?;
        Some((stream_data.socket.clone(), stream_data.bound_addr))
    }

    pub fn remove(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<SocketData<T>> {
        self.sockets.swap_remove(&(local_addr, remote_addr))
    }

    pub fn last_used(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) {
        if let Some(socket_data) = self.sockets.get_mut(&(local_addr, remote_addr)) {
            socket_data.last_used = Instant::now();
        }
    }

    pub fn cleanup(&mut self, older_than: Duration) -> usize {
        let current = self.sockets.len();
        self.sockets
            .retain(|_, d| Arc::strong_count(&d.socket) > 1 || d.last_used.elapsed() < older_than);
        current - self.sockets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cleanup() {
        let local_addr1 = "127.0.0.1:20000".parse().unwrap();
        let remote_addr1 = "127.0.0.1:20001".parse().unwrap();
        let local_addr2 = "127.0.0.1:20002".parse().unwrap();
        let remote_addr2 = "127.0.0.1:20003".parse().unwrap();
        let mut pool = SocketPool::new();
        pool.insert(local_addr1, remote_addr1, Arc::new(()));
        pool.insert(local_addr2, remote_addr2, Arc::new(()));

        assert_eq!(0, pool.cleanup(Duration::from_millis(1000)));
        assert_eq!(2, pool.cleanup(Duration::from_millis(0)));
    }
}
