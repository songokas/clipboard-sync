use assert_cmd::assert::Assert;
use assert_cmd::Command;
use predicates::prelude::*;
use rand::{distributions::Alphanumeric, Rng};
use std::io;
use std::process;
use std::thread;
use std::time::Duration;

const ANY_KEY: &'static str = "12345678912345678912345678912345";

fn send_receive_once(protocol: &'static str, size: usize) {
    let t1 = thread::spawn(move || {
        run_command(
            vec![
                "--key",
                ANY_KEY,
                "--bind-address",
                "0.0.0.0:8923",
                "--receive-once",
                "--allowed-host",
                "127.0.0.1:0",
                "--receive-once-wait",
                "1",
                "--protocol",
                protocol,
            ],
            "",
            3000,
        )
    });

    let contents: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect();

    let t2 = thread::spawn(move || {
        run_command(
            vec![
                "--key",
                ANY_KEY,
                "--bind-address",
                "0.0.0.0:8924",
                "--send-once",
                "--clipboard",
                "/dev/stdin",
                "--allowed-host",
                "127.0.0.1:8923",
                "--protocol",
                protocol,
            ],
            &contents,
            2000,
        )
    });

    let output1 = t1.join().unwrap().unwrap();
    let output2 = t2.join().unwrap().unwrap();

    let assert1 = Assert::new(output1);
    let assert2 = Assert::new(output2);

    assert1.stderr(predicate::str::contains("count 1"));
    assert2.stderr(predicate::str::contains("count 1"));
}

#[test]
fn test_send_receive_once() {
    for (protocol, size) in [
        ("basic", 10),
        ("basic", 10 * 1024 * 10),
        #[cfg(feature = "frames")]
        ("frames", 10 * 1024 * 10),
        ("laminar", 10 * 1024 * 10),
        #[cfg(feature = "quic")]
        ("quic", 10 * 1024 * 10),
    ]
    .to_vec()
    {
        send_receive_once(protocol, size);
    }
}

#[test]
#[ignore]
//cargo test test_receive_once_multicast -- --ignored
fn test_receive_once_multicast() {
    let t1 = thread::spawn(|| {
        run_command(
            vec![
                "--key",
                ANY_KEY,
                "--receive-once",
                "--receive-once-wait",
                "1",
                "--verbosity",
                "debug",
            ],
            "",
            10000,
        )
    });

    let output1 = t1.join().unwrap().unwrap();
    let assert1 = Assert::new(output1);
    assert1.stderr(predicate::str::contains("count 1"));
}

#[test]
#[ignore]
// cargo test test_send_once_multicast -- --ignored
fn test_send_once_multicast() {
    let t2 = thread::spawn(move || {
        run_command(
            vec!["--key", ANY_KEY, "--send-once", "--clipboard", "/dev/stdin"],
            "hello",
            2000,
        )
    });

    let output2 = t2.join().unwrap().unwrap();
    let assert2 = Assert::new(output2);
    assert2.stderr(predicate::str::contains("count 1"));
}

fn run_command(args: Vec<&'static str>, stdin: &str, timeout: u64) -> io::Result<process::Output> {
    let mut cmd = Command::cargo_bin("clipboard-sync").unwrap();
    for arg in args {
        cmd.arg(arg);
    }
    cmd.write_stdin(stdin);
    cmd.timeout(Duration::from_millis(timeout));
    return cmd.output();
}
