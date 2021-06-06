use assert_cmd::assert::Assert;
use assert_cmd::Command;
use predicates::prelude::*;
use rand::{distributions::Alphanumeric, Rng};
use std::fs::{create_dir_all, remove_dir, remove_file, write};
use std::io;
use std::process;
use std::thread;
use std::time::Duration;

const ANY_KEY: &'static str = "12345678912345678912345678912345";

fn send_receive_once(protocol: &'static str, size: usize)
{
    let bind_to = match protocol {
        #[cfg(feature = "quic-quinn")]
        "quic" => "[::1]:8923",
        _ => "127.0.0.1:8923",
    };

    let allowed_host = match protocol {
        #[cfg(feature = "quic-quinn")]
        "quic" => "[::1]:0",
        _ => "127.0.0.1:0",
    };
    let t1 = thread::spawn(move || {
        run_command(
            vec![
                "--key",
                ANY_KEY,
                "--bind-address",
                bind_to,
                "--receive-once",
                "--allowed-host",
                allowed_host,
                "--receive-once-wait",
                "1",
                "--protocol",
                protocol,
                #[cfg(feature = "quic")]
                "--cert-verify-dir",
                #[cfg(feature = "quic")]
                "tests/certs/cert-verify",
                #[cfg(feature = "quic")]
                "--private-key",
                #[cfg(feature = "quic")]
                "tests/certs/localhost.key",
                #[cfg(feature = "quic")]
                "--public-key",
                #[cfg(feature = "quic")]
                "tests/certs/localhost.crt",
            ],
            "",
            10000,
        )
    });

    let contents: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect();

    let send_to = match protocol {
        #[cfg(feature = "quic-quinn")]
        "quic" => "localhost:8923",
        _ => "127.0.0.1:8923",
    };

    thread::sleep(Duration::from_millis(100));

    let t2 = thread::spawn(move || {
        run_command(
            vec![
                "--key",
                ANY_KEY,
                "--send-using-address",
                "127.0.0.1:8934,[::1]:8934",
                "--send-once",
                "--clipboard",
                "/dev/stdin",
                "--allowed-host",
                send_to,
                "--protocol",
                protocol,
                #[cfg(feature = "quic")]
                "--cert-verify-dir",
                #[cfg(feature = "quic")]
                "tests/certs/cert-verify",
                #[cfg(feature = "quic")]
                "--private-key",
                #[cfg(feature = "quic")]
                "tests/certs/localhost.key",
                #[cfg(feature = "quic")]
                "--public-key",
                #[cfg(feature = "quic")]
                "tests/certs/localhost.crt",
            ],
            &contents,
            4000,
        )
    });

    let output1 = t1.join().unwrap().unwrap();
    let output2 = t2.join().unwrap().unwrap();

    // println!("{} {:?}", protocol, output1);
    // println!("{} {:?}", protocol, output2);

    let assert1 = Assert::new(output1);
    let assert2 = Assert::new(output2);

    assert2.stderr(predicate::str::contains("count 1"));
    assert1.stderr(predicate::str::contains("count 1"));
}

#[test]
fn test_send_receive_once()
{
    for (protocol, size) in [
        ("basic", 10),
        // ("basic", 10 * 1024 * 10),
        ("tcp", 10 * 1024 * 10),
        #[cfg(feature = "frames")]
        ("frames", 10 * 1024 * 10),
        ("laminar", 10 * 1024 * 10),
        #[cfg(feature = "quic-quinn")]
        ("quic", 10 * 1024 * 10),
        #[cfg(feature = "quic-quiche")]
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
fn test_send_once_multicast()
{
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

#[test]
fn test_send_heartbeat()
{
    let t2 = thread::spawn(move || {
        run_command(
            vec![
                "--key",
                ANY_KEY,
                "--clipboard",
                "/dev/stdin",
                "--ignore-initial-clipboard",
                "--heartbeat",
                "1",
                "--verbosity",
                "debug",
                "--bind-address",
                "0.0.0.0:0",
            ],
            "hello",
            3000,
        )
    });

    let output2 = t2.join().unwrap().unwrap();
    let assert2 = Assert::new(output2);
    assert2.stderr(predicate::str::contains("heartbeat"));
}

#[test]
fn test_file_changes()
{
    let file = "/tmp/test_file_changes";
    write(file, b"testdata1").unwrap();
    let t2 = thread::spawn(move || {
        run_command(
            vec![
                "--key",
                ANY_KEY,
                "--clipboard",
                file,
                "--ignore-initial-clipboard",
                "--verbosity",
                "debug",
                "--bind-address",
                "0.0.0.0:0",
            ],
            "hello",
            3000,
        )
    });
    thread::sleep(Duration::from_millis(100));
    write(file, b"testdata2").unwrap();
    let output2 = t2.join().unwrap().unwrap();
    remove_file(file).unwrap();

    let assert2 = Assert::new(output2);
    assert2.stderr(predicate::str::contains("Sent bytes"));
}

#[test]
fn test_file_changes_created_after_startup()
{
    let file = "/tmp/test_file_changes_created_after_startup";
    let t2 = thread::spawn(move || {
        run_command(
            vec![
                "--key",
                ANY_KEY,
                "--clipboard",
                file,
                "--ignore-initial-clipboard",
                "--verbosity",
                "debug",
                "--bind-address",
                "0.0.0.0:0",
            ],
            "hello",
            3000,
        )
    });
    thread::sleep(Duration::from_millis(100));
    write(file, b"testdata2").unwrap();
    let output2 = t2.join().unwrap().unwrap();
    remove_file(file).unwrap();

    let assert2 = Assert::new(output2);
    assert2.stderr(predicate::str::contains("Sent bytes"));
}

#[test]
fn test_directory_changes()
{
    let dir = "/tmp/test_directory_changes";
    create_dir_all(dir).unwrap();
    let file = format!("{}/_random_file", dir);
    write(&file, b"testdata1").unwrap();
    let t2 = thread::spawn(move || {
        run_command(
            vec![
                "--key",
                ANY_KEY,
                "--clipboard",
                dir,
                "--ignore-initial-clipboard",
                "--verbosity",
                "debug",
                "--bind-address",
                "0.0.0.0:0",
            ],
            "hello",
            3000,
        )
    });
    thread::sleep(Duration::from_millis(200));
    write(&file, b"testdata2").unwrap();
    let output2 = t2.join().unwrap().unwrap();
    remove_file(&file).unwrap();
    remove_dir(dir).unwrap();

    let assert2 = Assert::new(output2);
    assert2.stderr(predicate::str::contains("Sent bytes"));
}

#[test]
fn test_directory_changes_created_after_startup()
{
    let dir = "/tmp/test_directory_changes_created_after_startup";
    let file = format!("{}/file", dir);
    remove_file(&file).unwrap_or(());
    remove_dir(dir).unwrap_or(());
    let t2 = thread::spawn(move || {
        run_command(
            vec![
                "--key",
                ANY_KEY,
                "--clipboard",
                dir,
                "--ignore-initial-clipboard",
                "--verbosity",
                "debug",
                "--bind-address",
                "0.0.0.0:0",
            ],
            "hello",
            6000,
        )
    });
    thread::sleep(Duration::from_millis(1000));
    create_dir_all(dir).unwrap();
    // there is a delay between listen for directory and writting to file in that directory
    thread::sleep(Duration::from_millis(3000));
    write(&file, b"testdata1").unwrap();
    let output2 = t2.join().unwrap().unwrap();
    remove_file(&file).unwrap();
    remove_dir(dir).unwrap();

    let assert2 = Assert::new(output2);
    assert2.stderr(predicate::str::contains("Sent bytes"));
}

#[test]
fn test_send_receive_same_port()
{
    let size = 2000;
    let bind_to = "127.0.0.1:8928";
    let protocol = "basic";

    let allowed_host = "127.0.0.1:0";
    let t1 = thread::spawn(move || {
        run_command(
            vec![
                "--key",
                ANY_KEY,
                "--bind-address",
                bind_to,
                "--allowed-host",
                allowed_host,
                "--protocol",
                "basic",
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

    let send_to = "127.0.0.1:8928";

    thread::sleep(Duration::from_millis(100));

    let t2 = thread::spawn(move || {
        run_command(
            vec![
                "--key",
                ANY_KEY,
                "--bind-address",
                "127.0.0.1:8938,[::1]:8938",
                "--send-using-address",
                "127.0.0.1:8938,[::1]:8938",
                "--clipboard",
                "/dev/stdin",
                "--allowed-host",
                send_to,
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

    assert2.stderr(predicate::str::ends_with("protocol basic\n"));
    assert1.stderr(predicate::str::ends_with("protocol basic\n"));
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
