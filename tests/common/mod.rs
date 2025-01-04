use core::{str, time::Duration};

use assert_cmd::Command;
use insta_cmd::{get_cargo_bin, Info, Spawn};

pub fn run_command(
    args: Vec<&str>,
    timeout: Duration,
    stdin: &str,
    sort: bool,
    filter: Vec<String>,
) -> Cmd {
    let cmd = std::process::Command::new(get_cargo_bin("clipboard-sync"));
    run_command_by_name(cmd, args, timeout, stdin, sort, filter)
}

#[allow(dead_code)]
pub fn run_relay_command(
    args: Vec<&str>,
    timeout: Duration,
    stdin: &str,
    sort: bool,
    filter: Vec<String>,
) -> Cmd {
    let cmd = std::process::Command::new(get_cargo_bin("clipboard-relay"));
    run_command_by_name(cmd, args, timeout, stdin, sort, filter)
}

fn run_command_by_name(
    mut cmd: std::process::Command,
    mut args: Vec<&str>,
    timeout: Duration,
    stdin: &str,
    sort: bool,
    filter: Vec<String>,
) -> Cmd {
    if !args.contains(&"--verbosity") {
        args.extend(vec!["--verbosity", "info=simple"]);
    }
    for arg in args {
        cmd.arg(arg);
    }
    let info = Info::from_std_command(&cmd, None);
    let mut cmd = Command::from_std(cmd);
    cmd.write_stdin(stdin);
    cmd.timeout(timeout);
    Cmd {
        cmd,
        info,
        filter,
        sort,
    }
}

pub struct Cmd {
    cmd: Command,
    info: Info,
    filter: Vec<String>,
    sort: bool,
}

impl Spawn for Cmd {
    fn spawn_with_info(
        &mut self,
        _stdin: Option<Vec<u8>>,
    ) -> (Info, Option<String>, std::process::Output) {
        let mut output = self.cmd.output().unwrap();
        let mut description = None;
        if !self.filter.is_empty() || self.sort {
            description = String::from_utf8_lossy(&output.stderr).to_string().into();
            output.stderr = format_output(&output.stderr, &self.filter, self.sort);
        }
        (self.info.clone(), description, output)
    }
}

fn format_output(output: &[u8], filter: &[String], sort: bool) -> Vec<u8> {
    let str_output = str::from_utf8(output).unwrap();
    let mut lines: Vec<&str> = str_output
        .lines()
        .filter(|l| !filter.iter().any(|f| l.contains(f)))
        .collect();

    if sort {
        lines.sort();
    }
    lines.join("\n").as_bytes().to_vec()
}
