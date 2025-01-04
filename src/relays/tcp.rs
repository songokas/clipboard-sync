use core::cmp::min;
use core::ops::DerefMut;
use core::time::Duration;
use log::{debug, error, info, trace, warn};
use std::convert::TryInto;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::select;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::sleep;

use tokio::net::TcpListener;
use x25519_dalek::StaticSecret;

use crate::config::RelayConfig;
use crate::defaults::INIDICATION_SIZE;
use crate::errors::ConnectionError;
use crate::pools::destination_pool::DestinationPool;
use crate::pools::socket_pool::SocketPool;
use crate::stream::{obtain_data_with_size, write_to_stream};
use crate::validation::get_group_id;

const MAX_BUFFER_SIZE: usize = 10000;

pub async fn relay_data(
    listener: TcpListener,
    destination_pool: Arc<DestinationPool>,
    config: RelayConfig,
) -> u64 {
    let mut peek_handles: JoinSet<Result<(OwnedReadHalf, SocketAddr), ConnectionError>> =
        JoinSet::new();
    let mut stream_handles: JoinSet<Result<(OwnedReadHalf, u64, usize), ConnectionError>> =
        JoinSet::new();
    let stream_pool = Arc::new(Mutex::new(SocketPool::new()));
    let mut success_count = 0;

    loop {
        select! {
            new_stream = listener.accept() => {
                let Ok((stream, remote_addr)) = new_stream.inspect_err(|e| {
                        error!("Failed to accept tcp connection {}", e);
                }) else {
                    break;
                };

                debug!("New connection local_addr={} remote_addr={remote_addr}", stream.local_addr().expect("Bound address"));

                let (mut reader, writer) = stream.into_split();

                let stream_config = config.clone();
                let dpool = destination_pool.clone();
                let spool = stream_pool.clone();
                stream_handles.spawn(async move {
                    let (sent_count, data_size) = relay_stream(
                        &mut reader,
                        writer.into(),
                        &dpool,
                        spool,
                        stream_config,
                    )
                    .await?;
                    Ok((reader, sent_count, data_size))
                });
            }
            Some(stream_finished) = stream_handles.join_next(), if !stream_handles.is_empty() => {
                match stream_finished {
                    Ok(Ok((mut stream, sent_count, data_size))) => {
                        debug!("Relay finished total bytes sent,received {data_size} to {sent_count} destinations");
                        success_count += sent_count;
                        peek_handles.spawn(async move {
                            let peer_addr = stream.peer_addr()?;
                            peek_stream(&mut stream).await?;
                            Ok((stream, peer_addr))
                        });
                    }
                    Ok(Err(e)) => {
                        info!("Stream error: {e}");
                    }
                    Err(e) => {
                        debug!("Join error {e}");
                    }
                }
            }
            Some(stream_finished) = peek_handles.join_next(), if !peek_handles.is_empty() => {
                match stream_finished {
                Ok(Ok((mut stream, remote_addr))) => {
                    debug!("New data available for stream remote_addr={remote_addr}");

                    let stream_config = config.clone();
                    let dpool = destination_pool.clone();
                    let spool = stream_pool.clone();

                    stream_handles.spawn(async move {
                        let (sent_count, data_size) = relay_stream(
                            &mut stream,
                            None,
                            &dpool,
                            spool,
                            stream_config,
                        )
                        .await?;
                        Ok((stream, sent_count, data_size))
                    });
                }
                Ok(Err(e)) => {
                    info!("Stream error: {e}");
                }
                Err(e) => {
                    debug!("Join error {e}");
                }
            }
            }
        }
        stream_pool.lock().await.cleanup(config.keep_sockets_for);
        destination_pool.cleanup(config.keep_sockets_for);
    }
    success_count
}

async fn relay_stream(
    read_stream: &mut OwnedReadHalf,
    write_stream: Option<OwnedWriteHalf>,
    destination_pool: &DestinationPool,
    stream_pool: Arc<Mutex<SocketPool<Mutex<OwnedWriteHalf>>>>,
    config: RelayConfig,
) -> Result<(u64, usize), ConnectionError> {
    let mut total_read = 0;
    let from_addr = read_stream.peer_addr()?;

    debug!("New stream to relay from_addr={from_addr}");

    let relay_expected_indication_data =
        obtain_data_with_size(read_stream, INIDICATION_SIZE).await?;

    let relay_expected_size = u64::from_be_bytes(
        relay_expected_indication_data
            .clone()
            .try_into()
            .expect("Buffer must be 8 bytes long"),
    ) as usize;
    let message_details = obtain_data_with_size(read_stream, config.message_size).await?;
    total_read += message_details.len();

    let bound_addr = read_stream.local_addr().expect("Bound address");

    if let Some(w) = write_stream {
        stream_pool.lock().await.insert(
            bound_addr,
            read_stream.peer_addr()?,
            Arc::new(Mutex::new(w)),
        );
    }

    let mut client_expected_size_data = ((relay_expected_size - total_read) as u64)
        .to_be_bytes()
        .to_vec();

    let mut left_to_read = relay_expected_size - total_read;
    loop {
        let required_to_read = min(MAX_BUFFER_SIZE, left_to_read);

        // add client indication size
        let mut buffer = if !client_expected_size_data.is_empty() {
            let mut data = Vec::with_capacity(required_to_read);
            data.append(&mut client_expected_size_data);
            data
        } else {
            Vec::with_capacity(required_to_read)
        };
        loop {
            read_stream.readable().await?;

            match read_stream.read_buf(&mut buffer).await {
                // stream closed
                Ok(0) => {
                    return Err(ConnectionError::NoData);
                }
                Ok(read) => {
                    total_read += read;
                    left_to_read -= read;

                    trace!(
                        "Tcp stream received={read} total_read={total_read} relay_expected_size={relay_expected_size}"
                    );

                    if buffer.len() == required_to_read {
                        break;
                    }
                    continue;
                }
                Err(e) => {
                    error!("Failed to relay tcp connection {}", e);
                    return Err(ConnectionError::from(e));
                }
            };
        }

        let mut spool = stream_pool.lock().await;

        let destination_streams = get_streams_to_write(
            &message_details,
            destination_pool,
            &mut spool,
            bound_addr,
            from_addr,
            &config,
        )?;

        drop(spool);

        trace!(
            "Destinations to relay={} total={total_read} relay_expected_size={relay_expected_size}",
            destination_streams.len()
        );
        let sent_count = send_data(&destination_streams, &buffer, &from_addr).await;

        if total_read >= relay_expected_size {
            return Ok((sent_count, total_read));
        }
    }
}

async fn send_data(
    destination_streams: &[Arc<Mutex<OwnedWriteHalf>>],
    data: &[u8],
    from_addr: &SocketAddr,
) -> u64 {
    let mut success_count = 0;
    for stream in destination_streams {
        let mut destination_stream = stream.lock().await;
        let destination_addr = match destination_stream.peer_addr() {
            Ok(a) => a.to_string(),
            Err(_) => {
                error!(
                    "Tcp failed to send data with length {} unknown peer",
                    data.len(),
                );
                continue;
            }
        };

        if let Err(e) = write_to_stream(destination_stream.deref_mut(), data).await {
            error!("Tcp failed to send data with length {} {}", data.len(), e);
            continue;
        }

        trace!(
            "Relay from={from_addr} to={destination_addr} len={}",
            data.len()
        );
        success_count += 1;
    }
    success_count
}

fn get_streams_to_write(
    buffer: &[u8],
    destination_pool: &DestinationPool,
    stream_pool: &mut SocketPool<Mutex<OwnedWriteHalf>>,
    local_addr: SocketAddr,
    from_addr: SocketAddr,
    config: &RelayConfig,
) -> Result<Vec<Arc<Mutex<OwnedWriteHalf>>>, ConnectionError> {
    let group_id = match get_group_id(
        buffer,
        &StaticSecret::from(config.private_key),
        config.valid_for,
    ) {
        Ok(id) => id,
        Err(e) => {
            warn!(
                "Group id not found in data with len {}. {}",
                buffer.len(),
                e
            );
            return Err(e);
        }
    };
    destination_pool.add_destination(group_id, from_addr)?;

    let streams = destination_pool
        .get_destinations(&group_id)
        .into_iter()
        .filter_map(|d| {
            if d == from_addr {
                None
            } else {
                stream_pool.get(local_addr, d).map(|(s, _)| s.clone())
            }
        })
        .collect();
    Ok(streams)
}

pub async fn peek_stream(stream: &mut OwnedReadHalf) -> Result<(), ConnectionError> {
    let mut peek_buffer = [0; INIDICATION_SIZE];

    loop {
        stream.readable().await?;

        match stream.peek(&mut peek_buffer).await {
            Ok(s) if s == INIDICATION_SIZE => return Ok(()),
            Ok(_) => {
                // TODO await until data is available
                sleep(Duration::from_millis(300)).await;
                continue;
            }
            Err(e) => {
                return Err(ConnectionError::from(e));
            }
        }
    }
}
