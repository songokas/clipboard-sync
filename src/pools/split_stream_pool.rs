use core::{future::Future, net::SocketAddr};
use std::{sync::Arc, time::Duration};

use tokio::sync::{Mutex, Notify};

use crate::{
    errors::ConnectionError,
    stream::{ReadStream, WriteStream},
};

use super::socket_pool::{SocketPool, SocketState};

type LockedRead<T> = Mutex<T>;
type LockedWrite<T> = Arc<Mutex<T>>;
type LockedStateWrite<T, E> = Mutex<SocketState<LockedWrite<T>, E>>;

pub struct SplitStreamPool<R, W, E> {
    // local_addr, peer address, stream
    read_streams: Arc<Mutex<SocketPool<LockedRead<R>>>>,
    write_streams: Arc<Mutex<SocketPool<LockedStateWrite<W, E>>>>,
    notify: Arc<Notify>,
}

impl<R, W, E> Clone for SplitStreamPool<R, W, E> {
    fn clone(&self) -> Self {
        Self {
            read_streams: self.read_streams.clone(),
            write_streams: self.write_streams.clone(),
            notify: self.notify.clone(),
        }
    }
}

impl<R, W, E> Default for SplitStreamPool<R, W, E> {
    fn default() -> Self {
        Self {
            write_streams: Arc::new(Mutex::new(SocketPool::new())),
            read_streams: Arc::new(Mutex::new(SocketPool::new())),
            notify: Arc::new(Notify::new()),
        }
    }
}

impl<R, W, E> SplitStreamPool<R, W, E> {
    pub async fn wait_for_new_read_stream(
        &self,
        local_addr: SocketAddr,
    ) -> (Arc<LockedRead<R>>, SocketAddr) {
        loop {
            if let Some(stream) = self
                .read_streams
                .lock()
                .await
                .get_new_by_local_addr(local_addr)
            {
                return stream;
            }
            self.notify.notified().await;
        }
    }

    pub async fn obtain_write<F1, F2>(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        create_socket: impl Fn(SocketAddr, SocketAddr) -> F1,
        is_disconnected: impl Fn(Arc<LockedStateWrite<W, E>>) -> F2,
    ) -> Result<(Arc<LockedStateWrite<W, E>>, SocketAddr), ConnectionError>
    where
        F1: Future<Output = Result<(LockedStateWrite<W, E>, SocketAddr), ConnectionError>>,
        F2: Future<Output = bool>,
    {
        let mut pool = self.write_streams.lock().await;
        pool.obtain(local_addr, remote_addr, create_socket, is_disconnected)
            .await
    }

    pub async fn add_reader(&self, bound_addr: SocketAddr, stream: R) -> Result<(), std::io::Error>
    where
        R: ReadStream,
    {
        let remote_addr = stream.peer_addr()?;
        self.read_streams.lock().await.insert(
            bound_addr,
            remote_addr,
            Arc::new(Mutex::new(stream)),
        );
        self.notify.notify_one();
        Ok(())
    }

    pub async fn add_writer(&self, bound_addr: SocketAddr, stream: W) -> Result<(), std::io::Error>
    where
        W: WriteStream,
    {
        let remote_addr = stream.peer_addr()?;
        self.write_streams.lock().await.insert(
            bound_addr,
            remote_addr,
            Arc::new(Mutex::new(SocketState::Connected(Arc::new(Mutex::new(
                stream,
            ))))),
        );
        Ok(())
    }

    pub async fn last_used(&self, bound_addr: SocketAddr, remote_addr: SocketAddr) {
        self.write_streams
            .lock()
            .await
            .last_used(bound_addr, remote_addr);
        self.read_streams
            .lock()
            .await
            .last_used(bound_addr, remote_addr);
    }

    pub async fn remove(&self, bound_addr: SocketAddr, remote_addr: SocketAddr) {
        self.write_streams
            .lock()
            .await
            .remove(bound_addr, remote_addr);
        self.read_streams
            .lock()
            .await
            .remove(bound_addr, remote_addr);
    }

    /// returns (read streams removed, write streams removed)
    pub async fn cleanup(&self, older_than: Duration) -> (usize, usize) {
        let rcount = self.read_streams.lock().await.cleanup(older_than);
        let wcount = self.write_streams.lock().await.cleanup(older_than);
        (rcount, wcount)
    }
}

#[cfg(test)]
mod test {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, Interest},
        net::{TcpListener, TcpStream},
        time::{sleep, timeout},
    };

    use crate::pools::tcp_stream_pool::TcpStreamPool;

    use super::*;

    #[tokio::test]
    async fn test_stream_cleanup() {
        let pool = TcpStreamPool::default();

        let bind = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        let listener = TcpListener::bind(bind).await.unwrap();
        let bind = listener.local_addr().expect("Bound address");

        let cpool = pool.clone();
        let _handle = tokio::spawn(async move {
            loop {
                let (s, _) = listener.accept().await.unwrap();
                let (r, w) = s.into_split();
                cpool.add_writer(bind, w).await.unwrap();
                cpool.add_reader(bind, r).await.unwrap();
            }
        });

        let _stream1 = TcpStream::connect(bind).await.unwrap();
        let _stream2 = TcpStream::connect(bind).await.unwrap();
        assert_eq!((0, 0), pool.cleanup(Duration::from_secs(1)).await);
        assert_eq!((2, 2), pool.cleanup(Duration::ZERO).await);
    }

    #[tokio::test]
    async fn test_wait_for_new_read_stream() {
        let pool = TcpStreamPool::default();

        let bind = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        let listener = TcpListener::bind(bind).await.unwrap();
        let bind = listener.local_addr().expect("Bound address");

        let cpool = pool.clone();
        let _handle = tokio::spawn(async move {
            loop {
                let (s, _) = listener.accept().await.unwrap();
                let (r, w) = s.into_split();
                cpool.add_writer(bind, w).await.unwrap();
                cpool.add_reader(bind, r).await.unwrap();
            }
        });

        let _stream1 = TcpStream::connect(bind).await.unwrap();
        let _stream2 = TcpStream::connect(bind).await.unwrap();

        let _result = timeout(
            Duration::from_millis(100),
            pool.wait_for_new_read_stream(bind),
        )
        .await
        .unwrap();

        let _result = timeout(
            Duration::from_millis(100),
            pool.wait_for_new_read_stream(bind),
        )
        .await
        .unwrap();

        let result = timeout(
            Duration::from_millis(100),
            pool.wait_for_new_read_stream(bind),
        )
        .await;
        assert!(result.is_err());
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn test_connection_closed() {
        let bind = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        let listener = TcpListener::bind(bind).await.unwrap();
        let bind = listener.local_addr().expect("Bound address");

        let _handle = tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0; 10];
                assert_eq!(5, s.read(&mut buf).await.unwrap());
                // s.shutdown().await.unwrap();
            }
        });

        let mut stream1 = TcpStream::connect(bind).await.unwrap();

        let ready = stream1
            .ready(Interest::READABLE | Interest::WRITABLE)
            .await
            .unwrap();

        assert!(!ready.is_readable());
        assert!(!ready.is_read_closed());
        assert!(!ready.is_write_closed());

        let mut buf = [0; 10];
        // would block
        assert!(stream1.try_read(&mut buf).is_err());

        assert_eq!(5, stream1.try_write(b"hello").unwrap());
        assert!(stream1.peer_addr().is_ok());

        sleep(Duration::from_millis(100)).await;

        let ready = stream1
            .ready(Interest::READABLE | Interest::WRITABLE)
            .await
            .unwrap();

        assert!(ready.is_read_closed());
        assert!(ready.is_readable());
        assert!(!ready.is_write_closed());
        assert!(!ready.is_error());

        assert!(stream1.peer_addr().is_ok());
        assert_eq!(0, stream1.peek(&mut buf).await.unwrap());
        assert_eq!(0, stream1.try_read(&mut buf).unwrap());

        assert!(stream1.peer_addr().is_ok());
        assert_eq!(5, stream1.try_write(b"hello").unwrap());

        assert!(stream1.peer_addr().is_err());
        assert!(stream1.try_write(b"hello").is_err());
        assert!(stream1.peer_addr().is_err());

        assert!(stream1.shutdown().await.is_err());
        let ready = stream1
            .ready(Interest::READABLE | Interest::WRITABLE)
            .await
            .unwrap();
        // write closed never occurs
        assert!(!ready.is_error());
        assert!(ready.is_readable());
        assert!(ready.is_read_closed());
        // assert!(ready.is_write_closed());
    }
}
