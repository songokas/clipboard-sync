use assert_cmd::Command;
use predicates::prelude::*;
use std::time::Duration;

const ANY_KEY: &'static str = "12345678912345678912345678912345";

#[test]
fn test_send_once() {
    check_success(vec!["--key", ANY_KEY, "--bind-address", "127.0.0.1:8922", "--send-once"], "count 0"); 
}

#[test]
fn test_send_once_not_immediate() {
    check_success(vec!["--key", ANY_KEY, "--bind-address", "127.0.0.1:8923", "--send-once", "--ignore-initial-clipboard"], "clipboard changes"); 
}

#[test]
fn test_receive_once() {
    check_success(vec!["--key", ANY_KEY, "--bind-address", "127.0.0.1:8924", "--receive-once"], "Listen on"); 
}

#[test]

fn test_config() {
    check_success(vec!["--config", "tests/config.sample.yaml"], "from tests/config.sample.yaml"); 
}

#[test]

fn test_autogenerate() {
    check_success(vec!["--autogenerate"], "clipboard changes"); 
}

#[test]
fn test_failure_args() {

    for (args, expect) in get_failure_provider() {
        check_failure_arg(args, expect);
    }
}

fn check_failure_arg(args: Vec<&'static str>, expect: &str) -> Command
{
    let mut cmd = Command::cargo_bin("clipboard-sync").unwrap();
    for arg in args {
        cmd.arg(arg);
    }
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains(expect));
    return cmd;
}

fn check_success(args: Vec<&'static str>, expect: &str)
{
    let mut cmd = Command::cargo_bin("clipboard-sync").unwrap();
    for arg in args {
        cmd.arg(arg);
    }
    cmd.timeout(Duration::from_millis(2000));
    let output = cmd.assert();
    output.stderr(predicate::str::contains(expect));
}

fn get_failure_provider() ->Vec<(Vec<&'static str>, &'static str)>
{
    return vec![
        (vec!["--key", "3232"], "Current: 4"),
        (vec!["--config", "_1_unknow_path"], "_1_unknow_path"),
        (vec!["--key", ANY_KEY, "--unknown", "other"], "which wasn't expected"),
        (vec!["--key", ANY_KEY, "--send-using-address", "non-existing"], "non-existing"),
        (vec!["--key", ANY_KEY, "--bind-address", "non-existing"], "non-existing"),
        (vec!["--key", ANY_KEY, "--protocol", "non-existing"], "non-existing"),
    ]
}