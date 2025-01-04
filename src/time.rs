use chrono::Utc;

#[cfg(feature = "ntp")]
use crate::errors::ConnectionError;
use crate::errors::ValidationError;
#[cfg(feature = "ntp")]
use log::{debug, warn};
#[cfg(feature = "ntp")]
use rsntp::AsyncSntpClient;
#[cfg(feature = "ntp")]
use std::sync::atomic::AtomicI64;

#[cfg(feature = "ntp")]
use std::sync::atomic::Ordering;
use std::time::Duration;

#[cfg(feature = "ntp")]
static TIME_DIFF: AtomicI64 = AtomicI64::new(0);

pub fn get_time() -> u64 {
    #[cfg(feature = "ntp")]
    {
        let diff = TIME_DIFF.load(Ordering::Relaxed);
        let now = Utc::now().timestamp();
        (now + diff) as u64
    }
    #[cfg(not(feature = "ntp"))]
    return Utc::now().timestamp() as u64;
}

pub fn validate_timestamp(
    now: u64,
    timestamp: u64,
    max_expected: Duration,
) -> Result<(), ValidationError> {
    // let now = get_time();
    let difference = if now >= timestamp {
        now - timestamp
    } else {
        timestamp - now
    };
    if max_expected.as_secs() >= difference {
        Ok(())
    } else {
        Err(ValidationError::InvalidTimestamp {
            difference,
            max_expected,
        })
    }
}

#[cfg(feature = "ntp")]
pub async fn update_time_diff(
    ntp_address: String,
    cancel: tokio_util::sync::CancellationToken,
) -> crate::defaults::ExecutorResult {
    use tokio::{
        select,
        time::{self},
    };

    let mut interval = time::interval(Duration::from_secs(1800));
    let mut success_count = 0;
    loop {
        select! {
            _ = cancel.cancelled() => {
                debug!("Ntp cancelled");
                break;
            }
            _ = interval.tick() => {
                let diff = get_time_diff(&ntp_address).await;
                TIME_DIFF.fetch_add(diff, Ordering::Relaxed);
                success_count += 1;
            }
        }
    }
    Ok(("ntp", success_count))
}

#[cfg(feature = "ntp")]
async fn get_time_diff(ntp_address: &str) -> i64 {
    let real = if let Ok(t) = get_ntp_time(ntp_address).await {
        t as i64
    } else {
        return 0;
    };
    let now = Utc::now().timestamp();
    if real >= now {
        real - now
    } else {
        now - real
    }
}

#[cfg(feature = "ntp")]
async fn get_ntp_time(ntp_address: &str) -> Result<u64, ConnectionError> {
    let client = AsyncSntpClient::new();
    let result = client.synchronize(ntp_address).await.map_err(|e| {
        warn!("Failed to synchronize time: {}", e);
        ConnectionError::FailedToConnect(format!(
            "Failed to retrieve time from ntp server {} {}",
            ntp_address, e
        ))
    })?;
    let seconds = result
        .datetime()
        .unix_timestamp()
        .expect("ntp unix timestamp");
    debug!(
        "ntp time updated. server: {} utc time in seconds: {} utc local time: {}",
        ntp_address,
        seconds.as_secs(),
        Utc::now().timestamp()
    );
    Ok(seconds.as_secs())
}

#[cfg(test)]
mod tests {
    use test_data_file::test_data_file;

    use super::*;

    #[test]
    fn test_get_time() {
        assert!(get_time() > 0);
    }

    #[test_data_file(path = "tests/samples/validate_timestamp.csv")]
    #[test]
    fn test_validate_timestamp(now: u64, timestamp: u64, max_valid_secs: u64, is_ok: bool) {
        assert_eq!(
            validate_timestamp(now, timestamp, Duration::from_secs(max_valid_secs)).is_ok(),
            is_ok
        );
    }
}



