use chrono::Utc;
use std::convert::TryFrom;

#[cfg(feature = "ntp")]
use std::sync::atomic::{AtomicI64, Ordering};

#[cfg(feature = "ntp")]
use crate::errors::{CliError, ConnectionError};
#[cfg(feature = "ntp")]
use log::{debug, warn};
#[cfg(feature = "ntp")]
use rsntp::AsyncSntpClient;
#[cfg(feature = "ntp")]
use std::sync::atomic::AtomicBool;
#[cfg(feature = "ntp")]
use std::sync::Arc;
#[cfg(feature = "ntp")]
use std::time::Duration;
#[cfg(feature = "ntp")]
use std::time::Instant;
#[cfg(feature = "ntp")]
use tokio::time::sleep;

#[cfg(feature = "ntp")]
static TIME_DIFF: AtomicI64 = AtomicI64::new(0);

pub fn get_time() -> u64
{
    #[cfg(feature = "ntp")]
    {
        let diff = TIME_DIFF.load(Ordering::Relaxed);
        let now = Utc::now().timestamp();
        return (now + diff) as u64;
    }
    #[cfg(not(feature = "ntp"))]
    return Utc::now().timestamp() as u64;
}

pub fn is_timestamp_valid(timestamp: u64, valid_for: u16) -> bool
{
    if valid_for == 0 {
        return true;
    }
    let now = get_time();
    let timestamp_diff = if now >= timestamp {
        now - timestamp
    } else {
        timestamp - now
    };

    let diff = match u16::try_from(timestamp_diff) {
        Ok(i) => i,
        _ => return false,
    };
    return valid_for >= diff;
}

#[cfg(feature = "ntp")]
pub async fn update_time_diff(
    running: Arc<AtomicBool>,
    ntp_address: String,
) -> Result<(String, u64), CliError>
{
    let diff = get_time_diff(&ntp_address).await;
    TIME_DIFF.fetch_add(diff, Ordering::Relaxed);

    let mut now = Instant::now();
    let mut updated = 1;
    while running.load(Ordering::Relaxed) {
        sleep(Duration::from_millis(500)).await;

        if now.elapsed().as_secs() > 1800 {
            let diff = get_time_diff(&ntp_address).await;
            TIME_DIFF.fetch_add(diff, Ordering::Relaxed);
            now = Instant::now();
            updated += 1;
        }
    }
    return Ok((format!("ntp updated"), updated));
}

#[cfg(feature = "ntp")]
async fn get_time_diff(ntp_address: &str) -> i64
{
    let real = if let Ok(t) = get_ntp_time(ntp_address).await {
        t
    } else {
        return 0;
    };
    let now = Utc::now().timestamp();
    return if real >= now { real - now } else { now - real };
}

#[cfg(feature = "ntp")]
async fn get_ntp_time(ntp_address: &str) -> Result<i64, ConnectionError>
{
    let client = AsyncSntpClient::new();
    let result = client.synchronize(ntp_address).await.map_err(|e| {
        warn!("Failed to synchronize time: {}", e);
        ConnectionError::FailedToConnect(format!(
            "Failed to retrieve time from ntp server {} {}",
            ntp_address, e
        ))
    })?;
    let seconds = result.datetime().timestamp();
    debug!(
        "ntp time updated. server: {} utc time in seconds: {} utc local time: {}",
        ntp_address,
        seconds,
        Utc::now().timestamp()
    );
    return Ok(seconds);
}

#[cfg(test)]
mod timetest
{
    use super::*;

    #[test]
    fn test_get_time()
    {
        assert!(get_time() > 0);
    }

    #[test]
    fn is_timespamp_valid()
    {
        let now = get_time();
        assert!(is_timestamp_valid(now - 3, 3));
        assert!(!is_timestamp_valid(now - 4, 3));

        assert!(is_timestamp_valid(now + 3, 3));
        assert!(!is_timestamp_valid(now + 4, 3));

        assert!(is_timestamp_valid(now + 3, 0));
        assert!(is_timestamp_valid(now - 3, 0));
        assert!(is_timestamp_valid(0, 0));
    }
}
