use assert_cmd::Command;
use assert_cmd::assert::Assert;
use predicates::prelude::*;
use std::time::Duration;
use std::thread;
use std::io;
use std::process;
use rand::{distributions::Alphanumeric, Rng};

const ANY_KEY: &'static str = "12345678912345678912345678912345";

#[test]
fn test_send_receive_once_localhost()
{
    let t1 = thread::spawn(|| {
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
                "1"
            ],
            "",
            3000,
        )
    });
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
                "127.0.0.1:8923"
            ],
            "hello",
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
fn test_send_receive_once_frames()
{
    let t1 = thread::spawn(|| {
        run_command(
            vec![
                "--key",
                ANY_KEY,
                "--bind-address",
                "0.0.0.0:8953",
                "--receive-once",
                "--allowed-host",
                "127.0.0.1:0",
                "--receive-once-wait",
                "1",
                "--protocol",
                "frames"
            ],
            "",
            33000,
        )
    });
    let contents: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10 * 1024 * 1024)
        .map(char::from)
        .collect();
    let t2 = thread::spawn(move || {
        run_command(
            vec![
                "--key",
                ANY_KEY,
                "--bind-address",
                "0.0.0.0:8954",
                "--send-once",
                "--clipboard",
                "/dev/stdin",
                "--allowed-host",
                "127.0.0.1:8953",
                "--protocol",
                "frames"
            ],
            &contents,
            30000,
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
#[ignore] 
//cargo test test_receive_once_multicast -- --ignored
fn test_receive_once_multicast()
{
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
            vec![
                "--key",
                ANY_KEY,
                "--send-once",
                "--clipboard",
                "/dev/stdin"
            ],
            "hello",
            2000,
        )
    });

    let output2 = t2.join().unwrap().unwrap();
    let assert2 = Assert::new(output2);
    assert2.stderr(predicate::str::contains("count 1"));
}

fn run_command(args: Vec<&'static str>, stdin: &str, timeout: u64) -> io::Result<process::Output>
{
    let mut cmd = Command::cargo_bin("clipboard-sync").unwrap();
    for arg in args {
        cmd.arg(arg);
    }
    cmd.write_stdin(stdin);
    cmd.timeout(Duration::from_millis(timeout));
    return cmd.output();
}