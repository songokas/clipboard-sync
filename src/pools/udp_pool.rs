use core::{net::SocketAddr, time::Duration};
use std::sync::Arc;

use tokio::{net::UdpSocket, sync::Mutex};

use crate::{errors::ConnectionError, protocols::basic::obtain_client_socket};

use super::socket_pool::SocketPool;

#[derive(Debug)]
pub struct UdpData {
    pub socket: Arc<UdpSocket>,
    pub mutex: Mutex<()>,
}

#[derive(Clone)]
pub struct UdpSocketPool {
    sockets: Arc<Mutex<SocketPool<UdpData>>>,
}

impl Default for UdpSocketPool {
    fn default() -> Self {
        Self {
            sockets: Arc::new(Mutex::new(SocketPool::new())),
        }
    }
}

impl UdpSocketPool {
    pub async fn add(&self, socket: Arc<UdpSocket>) {
        let bound_addr = socket.local_addr().expect("Bound address");
        self.sockets.lock().await.insert(
            bound_addr,
            bound_addr,
            Arc::new(UdpData {
                socket,
                mutex: Mutex::new(()),
            }),
        );
    }

    pub async fn obtain(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<(Arc<UdpData>, SocketAddr), ConnectionError> {
        self.sockets
            .lock()
            .await
            .obtain(
                local_addr,
                local_addr,
                |_, _| create_socket(local_addr, remote_addr),
                |_| async { false },
            )
            .await
    }

    pub async fn remove(&self, bound_addr: SocketAddr) {
        self.sockets.lock().await.remove(bound_addr, bound_addr);
    }

    pub async fn last_used(&self, bound_addr: SocketAddr) {
        self.sockets.lock().await.last_used(bound_addr, bound_addr);
    }

    pub async fn cleanup(&self, older_than: Duration) -> usize {
        self.sockets.lock().await.cleanup(older_than)
    }
}

async fn create_socket(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> Result<(UdpData, SocketAddr), ConnectionError> {
    let socket = obtain_client_socket(local_addr, remote_addr).await?;
    let bound_addr = socket.local_addr().expect("Bound address");
    Ok((
        UdpData {
            socket: Arc::new(socket),
            mutex: Mutex::new(()),
        },
        bound_addr,
    ))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_obtain_by_specific_port() {
        let udp_pool = UdpSocketPool::default();
        let local_addr = "127.0.0.1:23001".parse().unwrap();
        let remote_addr = "127.0.0.1:23001".parse().unwrap();

        let socket1 = Arc::new(obtain_client_socket(local_addr, remote_addr).await.unwrap());
        udp_pool.add(socket1.clone()).await;

        let (socket_data, bind_address) = udp_pool.obtain(local_addr, remote_addr).await.unwrap();

        assert_eq!(socket1.local_addr().expect("Bound address"), bind_address);
        assert_eq!(
            socket1.local_addr().expect("Bound address"),
            socket_data.socket.local_addr().expect("Bound address")
        );
    }

    #[tokio::test]
    async fn test_always_obtain_new_socket() {
        let udp_pool = UdpSocketPool::default();
        let local_addr = "127.0.0.1:0".parse().unwrap();
        let remote_addr = "127.0.0.1:23002".parse().unwrap();

        let socket1 = Arc::new(obtain_client_socket(local_addr, remote_addr).await.unwrap());
        udp_pool.add(socket1.clone()).await;

        let (socket_data, bind_address) = udp_pool.obtain(local_addr, remote_addr).await.unwrap();

        assert_ne!(local_addr, bind_address);
        assert_ne!(socket1.local_addr().expect("Bound address"), bind_address);
        assert_ne!(
            socket1.local_addr().expect("Bound address"),
            socket_data.socket.local_addr().expect("Bound address")
        );

        let (same_data, same_bind) = udp_pool.obtain(local_addr, remote_addr).await.unwrap();

        assert_ne!(
            socket_data.socket.local_addr().expect("Bound address"),
            same_data.socket.local_addr().expect("Bound address")
        );
        assert_ne!(bind_address, same_bind);
    }

    #[tokio::test]
    async fn test_obtain_same_socket_with_different_remote() {
        let udp_pool = UdpSocketPool::default();
        let local_addr1 = "127.0.0.1:23003".parse().unwrap();
        let remote_addr1 = "127.0.0.1:23004".parse().unwrap();
        let remote_addr2 = "127.0.0.1:23005".parse().unwrap();

        let (socket_data, bind_address) = udp_pool.obtain(local_addr1, remote_addr1).await.unwrap();
        let (same_data, same_bind) = udp_pool.obtain(local_addr1, remote_addr2).await.unwrap();

        assert_eq!(
            socket_data.socket.local_addr().expect("Bound address"),
            same_data.socket.local_addr().expect("Bound address")
        );
        assert_eq!(bind_address, same_bind);
    }
}
