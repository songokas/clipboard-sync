use bytes::{Bytes, BytesMut};
use core::net::SocketAddr;
use log::{debug, trace};
use std::convert::TryInto;
use tokio::time::{timeout, Duration};
use tokio_util::bytes::BufMut;

use crate::defaults::INIDICATION_SIZE;
use crate::errors::ConnectionError;

#[allow(async_fn_in_trait)]
pub trait WriteStream {
    fn local_addr(&self) -> Result<SocketAddr, std::io::Error>;

    fn peer_addr(&self) -> Result<SocketAddr, std::io::Error>;

    async fn writable_stream(&mut self) -> Result<(), std::io::Error>;

    async fn write_buffer(&mut self, buffer: &[u8]) -> Result<usize, std::io::Error>;
}

#[allow(async_fn_in_trait)]
pub trait ReadStream {
    fn local_addr(&self) -> Result<SocketAddr, std::io::Error>;

    fn peer_addr(&self) -> Result<SocketAddr, std::io::Error>;

    async fn readable_stream(&mut self) -> Result<(), std::io::Error>;

    async fn read_buffer(&mut self, buffer: &mut impl BufMut) -> Result<usize, std::io::Error>;
}

pub async fn receive_stream(
    stream: &mut impl ReadStream,
    max_len: usize,
    wait_for: Duration,
) -> Result<Vec<u8>, ConnectionError> {
    debug!(
        "Tcp receive stream local_addr={} remote_addr={}",
        stream.local_addr()?,
        stream.peer_addr()?,
    );

    let expected_data =
        match timeout(wait_for, obtain_data_with_size(stream, INIDICATION_SIZE)).await {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(ConnectionError::Timeout("tcp receive", wait_for)),
        };
    let expected_size = u64::from_be_bytes(
        expected_data
            .try_into()
            .expect("Buffer must be 8 bytes long"),
    ) as usize;

    debug!("Received stream expected_size={expected_size}");

    if expected_size > max_len {
        return Err(ConnectionError::DataLimitReached {
            received: expected_size,
            max_len,
        });
    }

    obtain_data_with_size(stream, expected_size).await
}

pub async fn send_stream(
    stream: &mut impl WriteStream,
    data: Bytes,
) -> Result<usize, ConnectionError> {
    debug!(
        "Tcp send stream stream_size={} remote_addr={}",
        data.len(),
        stream.peer_addr()?
    );
    let mut bytes = BytesMut::new();
    bytes.put_u64(data.len() as u64);
    bytes.put(data);
    let data: Bytes = bytes.into();
    write_to_stream(stream, &data).await
}

pub async fn obtain_data_with_size(
    stream: &mut impl ReadStream,
    expected_size: usize,
) -> Result<Vec<u8>, ConnectionError> {
    let mut buffer = Vec::with_capacity(expected_size);
    loop {
        // stream.readable_stream().await?;

        match stream.read_buffer(&mut buffer).await {
            Ok(0) => {
                return Err(ConnectionError::NoData);
            }
            Ok(n) => {
                trace!(
                    "Read bytes={n} buffer={} local_addr={} remote_addr={} expected_size={expected_size}",
                    buffer.len(),
                    stream.local_addr()?,
                    stream.peer_addr()?
                );
                if buffer.len() >= expected_size {
                    return Ok(buffer);
                }
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        };
    }
}

pub async fn write_to_stream(
    stream: &mut impl WriteStream,
    data_to_send: &[u8],
) -> Result<usize, ConnectionError> {
    let mut total_written = 0;
    loop {
        stream.writable_stream().await?;
        match stream.write_buffer(&data_to_send[total_written..]).await {
            Ok(n) => {
                total_written += n;
                trace!(
                    "Sent bytes={total_written} local_addr={} remote_addr={} expected_size={}",
                    stream.local_addr()?,
                    stream.peer_addr()?,
                    data_to_send.len()
                );
                if total_written >= data_to_send.len() {
                    return Ok(total_written);
                }
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
}
