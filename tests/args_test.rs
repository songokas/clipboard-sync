use core::time::Duration;

use insta_cmd::assert_cmd_snapshot;

mod common;

use crate::common::run_command;

const ANY_KEY: &str = "12345678912345678912345678912345";

#[test]
fn test_send_once() {
    assert_cmd_snapshot!(run_command(
        vec![
            "--key",
            ANY_KEY,
            "--bind-address",
            "127.0.0.1:8922",
            "--send-once",
            "--clipboard",
            "tests/temp1"
        ],
        Duration::from_secs(2),
        "",
        false,
        vec![],
    ));
}

#[test]
fn test_bind_send_multiple_addresses() {
    assert_cmd_snapshot!(run_command(
        vec![
            "--key",
            ANY_KEY,
            "--bind-address",
            "127.0.0.1:12390,[::1]:12390",
            "--send-using-address",
            "127.0.0.1:12390,[::1]:12390",
            "--send-once",
            "--allowed-host",
            "127.0.0.1:8911,[::1]:8911",
            "--clipboard",
            "tests/temp1"
        ],
        Duration::from_secs(2),
        "",
        true,
        vec![],
    ));
}

#[test]
fn test_send_once_not_immediate() {
    assert_cmd_snapshot!(run_command(
        vec![
            "--key",
            ANY_KEY,
            "--bind-address",
            "127.0.0.1:8923",
            "--send-once",
            "--ignore-initial-clipboard",
        ],
        Duration::from_secs(2),
        "",
        false,
        vec![],
    ));
}

#[test]
fn test_receive_once() {
    assert_cmd_snapshot!(run_command(
        vec![
            "--key",
            ANY_KEY,
            "--bind-address",
            "127.0.0.1:8924",
            "--receive-once",
        ],
        Duration::from_secs(2),
        "",
        true,
        vec![],
    ));
}

#[test]
fn test_config() {
    assert_cmd_snapshot!(run_command(
        vec!["--config", "tests/config.sample.yaml"],
        Duration::from_secs(2),
        "",
        true,
        vec![],
    ));
}

#[test]
fn test_failure_args() {
    for (args, snapshot_name) in get_failure_provider() {
        assert_cmd_snapshot!(
            snapshot_name,
            run_command(args, Duration::from_secs(2), "", false, vec![],)
        );
    }
}

#[test]
fn test_default_with_protocols() {
    for protocol in ["basic", "tcp", "tcp-tls", "quic"] {
        assert_cmd_snapshot!(
            format!("test_default_with_protocols_{protocol}"),
            run_command(
                vec![
                    "--protocol",
                    protocol,
                    "--key",
                    ANY_KEY,
                    "--bind-address",
                    "[::]:12001",
                    "--allowed-host",
                    "[::1]:0",
                    "--ignore-initial-clipboard"
                ],
                Duration::from_secs(2),
                "",
                false,
                vec![],
            )
        );
    }
}

fn get_failure_provider() -> Vec<(Vec<&'static str>, &'static str)> {
    vec![
        (vec!["--key", "3232"], "invalid_key"),
        (vec!["--config", "_1_unknow_path"], "unknown_config_path"),
        (
            vec!["--key", ANY_KEY, "--unknown", "other"],
            "unexpected argument",
        ),
        (
            vec!["--key", ANY_KEY, "--send-using-address", "non-existing"],
            "non-existing-send-address",
        ),
        (
            vec!["--key", ANY_KEY, "--bind-address", "non-existing"],
            "non-existing-bind-address",
        ),
        (
            vec!["--key", ANY_KEY, "--protocol", "non-existing"],
            "non-existing-protocol",
        ),
    ]
}
