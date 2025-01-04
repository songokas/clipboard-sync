use core::{future::Future, net::SocketAddr, ops::Deref, time::Duration};
use std::sync::Arc;

use quinn::{Connection, Endpoint};
use tokio::sync::{Mutex, Notify};

use crate::errors::ConnectionError;

use super::socket_pool::{SocketPool, SocketState};

type WriteSocketState = Mutex<SocketState<Arc<Connection>, Endpoint>>;

#[derive(Clone)]
pub struct ConnectionPool {
    connections: Arc<Mutex<SocketPool<WriteSocketState>>>,
    server_endpoint: Arc<Mutex<Option<(Endpoint, SocketAddr)>>>,
    notify: Arc<Notify>,
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self {
            connections: Arc::new(Mutex::new(SocketPool::new())),
            notify: Arc::new(Notify::new()),
            server_endpoint: Arc::new(Mutex::new(None)),
        }
    }
}

impl ConnectionPool {
    pub async fn wait_for_new_read_stream(
        &self,
        local_addr: SocketAddr,
    ) -> (Arc<Connection>, SocketAddr) {
        loop {
            if let Some((socket_state, remote_addr)) = self
                .connections
                .lock()
                .await
                .get_new_by_local_addr(local_addr)
            {
                match socket_state.lock().await.deref() {
                    SocketState::Connected(c) => return (c.clone(), remote_addr),
                    SocketState::NotConnected(_) => (),
                };
            }
            self.notify.notified().await;
        }
    }

    pub async fn obtain<C, F>(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        create_socket: C,
    ) -> Result<(Arc<WriteSocketState>, SocketAddr), ConnectionError>
    where
        C: Fn(SocketAddr, SocketAddr) -> F,
        F: Future<Output = Result<(WriteSocketState, SocketAddr), ConnectionError>>,
    {
        let mut pool = self.connections.lock().await;
        pool.obtain(local_addr, remote_addr, create_socket, is_disconnected)
            .await
    }

    pub async fn add(&self, connection: Arc<Connection>, bound_addr: SocketAddr) {
        self.connections.lock().await.insert(
            bound_addr,
            connection.remote_address(),
            Arc::new(Mutex::new(SocketState::Connected(connection))),
        );
    }

    pub async fn remove(&self, bound_addr: SocketAddr, remote_addr: SocketAddr) {
        self.connections
            .lock()
            .await
            .remove(bound_addr, remote_addr);
    }

    pub async fn last_used(&self, bound_addr: SocketAddr, remote_addr: SocketAddr) {
        self.connections
            .lock()
            .await
            .last_used(bound_addr, remote_addr);
    }

    pub fn notify(&self) {
        self.notify.notify_one();
    }

    pub async fn add_server_endpoint(&self, endpoint: Endpoint, bound_addr: SocketAddr) {
        *self.server_endpoint.lock().await = Some((endpoint, bound_addr));
    }

    pub async fn server_endpoint(&self, local_addr: SocketAddr) -> Option<Endpoint> {
        self.server_endpoint
            .lock()
            .await
            .as_ref()
            .and_then(|(e, l)| (l == &local_addr).then(|| e.clone()))
    }

    pub async fn cleanup(&self, older_than: Duration) -> usize {
        self.connections.lock().await.cleanup(older_than)
    }
}

async fn is_disconnected(socket_state: Arc<Mutex<SocketState<Arc<Connection>, Endpoint>>>) -> bool {
    match socket_state.try_lock().as_deref() {
        Ok(SocketState::Connected(c)) => c.close_reason().is_some(),
        Ok(SocketState::NotConnected(None)) => true,
        _ => false,
    }
}
