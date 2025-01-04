use clipboard_sync::protocol::Protocol;
use common::run_relay_command;
use insta_cmd::assert_cmd_snapshot;
use rand::{distributions::Alphanumeric, Rng};
use std::thread;
use std::time::Duration;
use test_data_file::test_data_file;

mod common;

use crate::common::run_command;

const ENCRYPTION_KEY: &str = "12345678912345678912345678912345";
const PRIVATE_KEY: &str = "33232323233323233333333333333333";
const PUBLIC_KEY: &str = "Bj3xcJXgG4kuRolMZrIbbfY1wajtjPr4ssxSqFFhaGk=";

#[test_data_file(path = "tests/samples/relay.list")]
#[test]
fn relay_protocol(protocol: Protocol, size: usize) {
    let relay_bind = "127.0.0.1:8922";

    let t1 = thread::spawn(move || {
        assert_cmd_snapshot!(
            format!("relay_{protocol}_{size}"),
            run_relay_command(
                vec![
                    "--private-key",
                    PRIVATE_KEY,
                    "--bind-address",
                    relay_bind,
                    "--protocol",
                    &protocol.to_string(),
                    "--verbosity",
                    "debug=simple",
                ],
                Duration::from_millis(6000),
                "",
                true,
                vec![],
            )
        )
    });

    let contents: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect();
    let bind_to2 = "127.0.0.1:8923";

    thread::sleep(Duration::from_millis(200));

    let t2 = thread::spawn(move || {
        assert_cmd_snapshot!(
            format!("server_{protocol}_{size}"),
            run_command(
                vec![
                    "--key",
                    ENCRYPTION_KEY,
                    "--bind-address",
                    bind_to2,
                    "--send-using-address",
                    bind_to2,
                    "--allowed-host",
                    "127.0.0.1:8922",
                    "--protocol",
                    &protocol.to_string(),
                    "--relay-host",
                    relay_bind,
                    "--relay-public-key",
                    PUBLIC_KEY,
                    "--verbosity",
                    "debug=simple",
                    "--clipboard",
                    "/dev/stdin",
                    "--heartbeat",
                    "20",
                ],
                Duration::from_millis(6000),
                &contents,
                true,
                vec![],
            )
        )
    });

    let contents: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect();
    // let expected_size = contents.len();

    let bind_to3 = "127.0.0.1:8924";

    thread::sleep(Duration::from_millis(200));

    let t3 = thread::spawn(move || {
        assert_cmd_snapshot!(
            format!("client_{protocol}_{size}"),
            run_command(
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
                    &protocol.to_string(),
                    "--relay-host",
                    relay_bind,
                    "--relay-public-key",
                    PUBLIC_KEY,
                    "--verbosity",
                    "debug=simple",
                    "--clipboard",
                    "/dev/stdin",
                    "--heartbeat",
                    "20",
                ],
                Duration::from_millis(6000),
                &contents,
                true,
                vec![],
            )
        )
    });

    let _ = t1.join();
    let _ = t2.join();
    let _ = t3.join();
}
