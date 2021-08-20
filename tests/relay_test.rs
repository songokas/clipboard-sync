use assert_cmd::assert::Assert;
use assert_cmd::Command;
use predicates::prelude::*;
use rand::{distributions::Alphanumeric, Rng};
use std::io;
use std::process;
use std::thread;
use std::time::Duration;

const ENCRYPTION_KEY: &str = "12345678912345678912345678912345";
const PRIVATE_KEY: &str = "33232323233323233333333333333333";
const PUBLIC_KEY: &str = "Bj3xcJXgG4kuRolMZrIbbfY1wajtjPr4ssxSqFFhaGk=";

fn relay_protocol(protocol: &'static str, size: usize)
{
    let relay_bind = "127.0.0.1:8922";

    let t1 = thread::spawn(move || {
        run_command(
            "clipboard-relay",
            vec![
                "--private-key",
                PRIVATE_KEY,
                "--bind-address",
                relay_bind,
                "--protocol",
                protocol,
                "--verbosity",
                "debug",
            ],
            "",
            2000,
        )
    });

    let contents: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect();
    let bind_to2 = match protocol {
        #[cfg(feature = "quic-quinn")]
        "quic" => "[::1]:8923",
        _ => "127.0.0.1:8923",
    };

    thread::sleep(Duration::from_millis(100));

    let t2 = thread::spawn(move || {
        run_command(
            "clipboard-sync",
            vec![
                "--key",
                ENCRYPTION_KEY,
                "--bind-address",
                bind_to2,
                "--send-using-address",
                bind_to2,
                "--allowed-host",
                relay_bind,
                "--protocol",
                protocol,
                "--relay-host",
                relay_bind,
                "--relay-public-key",
                PUBLIC_KEY,
                "--verbosity",
                "debug",
                "--clipboard",
                "/dev/stdin",
                "--ntp-server",
                "",
                "--heartbeat",
                "20",
            ],
            &contents,
            2000,
        )
    });

    let contents: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect();
    let bind_to3 = match protocol {
        #[cfg(feature = "quic-quinn")]
        "quic" => "[::1]:8924",
        _ => "127.0.0.1:8924",
    };

    thread::sleep(Duration::from_millis(100));

    let t3 = thread::spawn(move || {
        run_command(
            "clipboard-sync",
            vec![
                "--key",
                ENCRYPTION_KEY,
                "--bind-address",
                bind_to3,
                "--send-using-address",
                bind_to3,
                "--allowed-host",
                relay_bind,
                "--protocol",
                protocol,
                "--relay-host",
                relay_bind,
                "--relay-public-key",
                PUBLIC_KEY,
                "--verbosity",
                "debug",
                "--clipboard",
                "/dev/stdin",
                "--ntp-server",
                "",
                "--heartbeat",
                "20",
            ],
            &contents,
            2000,
        )
    });

    let output1 = t1.join().unwrap().unwrap();
    let output2 = t2.join().unwrap().unwrap();
    let output3 = t3.join().unwrap().unwrap();

    let assert1 = Assert::new(output1);
    let assert_sent = Assert::new(output2.clone());
    let assert_received = Assert::new(output2);
    let assert3 = Assert::new(output3);

    assert1.stderr(predicate::str::contains(
        "from 127.0.0.1:8924 to 127.0.0.1:8923",
    ));
    assert_sent.stderr(predicate::str::contains("Sent bytes"));
    assert_received.stderr(predicate::str::contains(
        "Packet received from 127.0.0.1:8922",
    ));
    assert3.stderr(predicate::str::contains("Sent bytes"));
}

#[test]
fn test_relay()
{
    for (protocol, size) in [("basic", 10), ("tcp", 10), ("laminar", 10)].to_vec() {
        relay_protocol(protocol, size);
    }
}

fn run_command(
    command: &str,
    args: Vec<&'static str>,
    stdin: &str,
    timeout: u64,
) -> io::Result<process::Output>
{
    let mut cmd = Command::cargo_bin(command).unwrap();
    for arg in args {
        cmd.arg(arg);
    }
    cmd.write_stdin(stdin);
    cmd.timeout(Duration::from_millis(timeout));
    cmd.output()
}
