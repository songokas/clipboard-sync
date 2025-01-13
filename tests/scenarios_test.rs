use clipboard_sync::protocol::Protocol;
use insta_cmd::assert_cmd_snapshot;
use rand::{distributions::Alphanumeric, Rng};
use std::fs::{create_dir_all, remove_dir, remove_file, write};
use std::thread;
use std::time::Duration;
use test_data_file::test_data_file;

mod common;

use crate::common::run_command;

const ANY_KEY: &str = "12345678912345678912345678912345";

#[test]
#[ignore]
//cargo test test_receive_once_multicast -- --ignored
fn test_receive_once_multicast() {
    assert_cmd_snapshot!(run_command(
        vec![
            "--key",
            ANY_KEY,
            "--receive-once",
            "--receive-once-wait",
            "1",
            "--verbosity",
            "debug",
        ],
        Duration::from_secs(10),
        "",
        true,
        vec![],
    ));
}

#[test]
#[ignore]
// cargo test test_send_once_multicast -- --ignored
fn test_send_once_multicast() {
    assert_cmd_snapshot!(run_command(
        vec!["--key", ANY_KEY, "--send-once", "--clipboard", "/dev/stdin"],
        Duration::from_secs(2),
        "hello",
        true,
        vec![],
    ));
}

#[test]
fn test_send_heartbeat_without_sending_clipboard_data() {
    assert_cmd_snapshot!(run_command(
        vec![
            "--key",
            ANY_KEY,
            "--clipboard",
            "/dev/stdin",
            "--ignore-initial-clipboard",
            "--heartbeat",
            "10",
            "--verbosity",
            "debug=simple",
            "--bind-address",
            "0.0.0.0:33321",
        ],
        Duration::from_secs(3),
        "hello",
        true,
        vec![],
    ));
}

#[test]
fn test_file_changes() {
    let file = "/tmp/test_file_changes";
    let _ = remove_file(file);
    write(file, b"testdata1").unwrap();
    let t1 = thread::spawn(move || {
        assert_cmd_snapshot!(run_command(
            vec![
                "--key",
                ANY_KEY,
                "--clipboard",
                file,
                "--ignore-initial-clipboard",
                "--verbosity",
                "debug=simple",
                "--bind-address",
                "0.0.0.0:33322",
            ],
            Duration::from_secs(3),
            "hello",
            true,
            vec![],
        ))
    });
    thread::sleep(Duration::from_millis(1000));
    write(file, b"testdata2").unwrap();
    t1.join().unwrap();
    remove_file(file).unwrap();
}

#[test]
fn test_file_changes_created_after_startup() {
    let dir = "/tmp/_test_file_changes_created_after_startup";
    create_dir_all(dir).unwrap();
    let file = format!("{dir}/file");
    remove_file(&file).unwrap_or(());
    let cfile = file.clone();
    let t1 = thread::spawn(move || {
        assert_cmd_snapshot!(run_command(
            vec![
                "--key",
                ANY_KEY,
                "--clipboard",
                &cfile,
                "--ignore-initial-clipboard",
                "--verbosity",
                "debug=simple",
                "--bind-address",
                "0.0.0.0:33323",
            ],
            Duration::from_secs(3),
            "hello",
            true,
            vec![],
        ))
    });
    thread::sleep(Duration::from_millis(1000));
    write(&file, b"testdata2").unwrap();
    t1.join().unwrap();
    remove_file(file).unwrap();
}

#[test]
fn test_directory_changes() {
    let dir = "/tmp/_test_directory_changes";
    create_dir_all(dir).unwrap();
    let file = format!("{}/_random_file", dir);
    write(&file, b"testdata1").unwrap();
    let t1 = thread::spawn(move || {
        assert_cmd_snapshot!(run_command(
            vec![
                "--key",
                ANY_KEY,
                "--clipboard",
                dir,
                "--ignore-initial-clipboard",
                "--verbosity",
                "debug=simple",
                "--bind-address",
                "0.0.0.0:33324",
            ],
            Duration::from_secs(3),
            "hello",
            true,
            vec![],
        ))
    });
    thread::sleep(Duration::from_millis(1000));
    write(&file, b"testdata2").unwrap();
    t1.join().unwrap();
    remove_file(&file).unwrap();
    remove_dir(dir).unwrap();
}

#[test]
fn test_directory_changes_created_after_startup() {
    let dir = "/tmp/_test_directory_changes_created_after_startup/dir";
    create_dir_all(dir).unwrap();
    let file = format!("{}/file", dir);
    remove_file(&file).unwrap_or(());
    remove_dir(dir).unwrap_or(());
    let t1 = thread::spawn(move || {
        assert_cmd_snapshot!(run_command(
            vec![
                "--key",
                ANY_KEY,
                "--clipboard",
                dir,
                "--ignore-initial-clipboard",
                "--verbosity",
                "debug=simple",
                "--bind-address",
                "0.0.0.0:33325",
            ],
            Duration::from_secs(6),
            "hello",
            true,
            vec![],
        ))
    });
    thread::sleep(Duration::from_millis(1000));
    create_dir_all(dir).unwrap();
    // there is a delay between listen for directory and writing to file in that directory
    thread::sleep(Duration::from_millis(2000));
    write(&file, b"testdata1").unwrap();
    thread::sleep(Duration::from_millis(1000));
    t1.join().unwrap();
    remove_file(&file).unwrap();
    remove_dir(dir).unwrap();
}

#[test_data_file(path = "tests/samples/send_receive_same_port.list")]
#[test]
fn test_send_receive_same_port(protocol: Protocol) {
    let size = 2000;

    let bind_to = "127.0.0.1:12910";
    let allowed_host = "127.0.0.1:12911=localhost";

    let t1 = thread::spawn(move || {
        assert_cmd_snapshot!(
            format!("test_send_receive_same_port_client1_{protocol}"),
            run_command(
                vec![
                    "--verbosity",
                    "debug=simple",
                    "--key",
                    ANY_KEY,
                    "--bind-address",
                    bind_to,
                    "--send-using-address",
                    bind_to,
                    "--allowed-host",
                    allowed_host,
                    "--protocol",
                    &protocol.to_string(),
                    "--clipboard",
                    "/dev/stdin",
                    "--remote-certificates",
                    "tests/certs/cert-verify/for-client",
                    "--private-key",
                    "tests/certs/testclient.key",
                    "--certificate-chain",
                    "tests/certs/testclient.crt",
                ],
                Duration::from_secs(3),
                "client that sends",
                true,
                vec![
                    "drive; id".to_string(),
                    "TLS1.3 encrypted extensions".to_string(),
                    "Got CertificateRequest CertificateRequestPayloadTls13".to_string(),
                ],
            )
        )
    });

    let contents: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect();

    thread::sleep(Duration::from_millis(100));

    let allowed_host = "127.0.0.1:12910=testclient";
    let bind_to = "127.0.0.1:12911";

    let t2 = thread::spawn(move || {
        assert_cmd_snapshot!(
            format!("test_send_receive_same_port_client2_{protocol}"),
            run_command(
                vec![
                    "--verbosity",
                    "debug=simple",
                    "--key",
                    ANY_KEY,
                    "--bind-address",
                    bind_to,
                    "--send-using-address",
                    bind_to,
                    "--clipboard",
                    "/dev/stdin",
                    "--allowed-host",
                    allowed_host,
                    "--protocol",
                    &protocol.to_string(),
                    "--remote-certificates",
                    "tests/certs/cert-verify/for-server",
                    "--private-key",
                    "tests/certs/localhost.key",
                    "--certificate-chain",
                    "tests/certs/localhost.crt",
                ],
                Duration::from_secs(3),
                &contents,
                true,
                vec![
                    "drive; id".to_string(),
                    "TLS1.3 encrypted extensions".to_string(),
                    "Got CertificateRequest CertificateRequestPayloadTls13".to_string(),
                ],
            )
        )
    });

    t1.join().unwrap();
    t2.join().unwrap();
}

#[test_data_file(path = "tests/samples/send_receive_once.list")]
#[test]
fn test_send_receive_once(protocol: Protocol, size: usize) {
    let bind_to = "127.0.0.1:12903,[::1]:12903";
    let allowed_host = "127.0.0.1:0,[::1]:0";

    let t1 = thread::spawn(move || {
        assert_cmd_snapshot!(
            format!("test_send_receive_once_server_{protocol}_{size}"),
            run_command(
                vec![
                    "--verbosity",
                    "debug=simple",
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
                    &protocol.to_string(),
                    "--remote-certificates",
                    "tests/certs/cert-verify/for-server",
                    "--private-key",
                    "tests/certs/localhost.key",
                    "--certificate-chain",
                    "tests/certs/localhost.crt",
                ],
                Duration::from_secs(10),
                "",
                true,
                vec![
                    "drive; id".to_string(),
                    "TLS1.3 encrypted extensions".to_string(),
                    "Got CertificateRequest CertificateRequestPayloadTls13".to_string(),
                ],
            )
        )
    });

    let contents: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect();

    let send_to = "127.0.0.1:12903=localhost";

    thread::sleep(Duration::from_millis(100));

    let t2 = thread::spawn(move || {
        assert_cmd_snapshot!(
            format!("test_send_receive_once_client_{protocol}_{size}"),
            run_command(
                vec![
                    "--verbosity",
                    "debug=simple",
                    "--key",
                    ANY_KEY,
                    "--send-using-address",
                    "127.0.0.1:12904,[::1]:12904",
                    "--send-once",
                    "--clipboard",
                    "/dev/stdin",
                    "--allowed-host",
                    send_to,
                    "--protocol",
                    &protocol.to_string(),
                    "--remote-certificates",
                    "tests/certs/cert-verify/for-client",
                    "--private-key",
                    "tests/certs/testclient.key",
                    "--certificate-chain",
                    "tests/certs/testclient.crt",
                ],
                Duration::from_secs(4),
                &contents,
                true,
                vec![
                    "drive; id".to_string(),
                    "TLS1.3 encrypted extensions".to_string(),
                    "Got CertificateRequest CertificateRequestPayloadTls13".to_string(),
                ],
            )
        )
    });

    t1.join().unwrap();
    t2.join().unwrap();
}
