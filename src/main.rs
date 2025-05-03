#![no_std]
#![no_main]
#![doc = include_str!("../README.md")]

#[macro_use]
extern crate axlog;
extern crate alloc;
extern crate axruntime;

mod entry;
mod mm;
mod syscall;

use alloc::{string::String, vec::Vec};
use axprocess::Process;
use axtask::current;

fn parse_cmd(cmd: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current_arg = String::new();
    let mut in_quotes = false;

    for c in cmd.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            ' ' if !in_quotes => {
                if !current_arg.is_empty() {
                    args.push(current_arg.clone());
                    current_arg.clear();
                }
            }
            _ => current_arg.push(c),
        }
    }

    if !current_arg.is_empty() {
        args.push(current_arg);
    }

    args
}

fn run_single_testcase(testcase: &str) {
    error!("Start running user task {}", testcase);
    let args = testcase
        .split_ascii_whitespace()
        .map(Into::into)
        .collect::<Vec<_>>();

    let exit_code = entry::run_user_app(&args, &[]);
    error!("User task {} exited with code: {:?}", testcase, exit_code);
}

fn list_all_testcases() {
    let testcases = option_env!("AX_TESTCASES_LIST")
        .unwrap_or_else(|| "Please specify the testcases list by making user_apps")
        .split(',')
        .filter(|&x| !x.is_empty());

    for testcase in testcases {
        error!("{} ", testcase);
    }
}

fn run_all_testcases() {
    let testcases = option_env!("AX_TESTCASES_LIST")
        .unwrap_or_else(|| "Please specify the testcases list by making user_apps")
        .split(',')
        .filter(|&x| !x.is_empty());

    for testcase in testcases {
        let args = testcase
            .split_ascii_whitespace()
            .map(Into::into)
            .collect::<Vec<_>>();
        let exit_code = entry::run_user_app(&args, &[]);
        error!("User task {} exited with code: {:?}", testcase, exit_code);
    }
}

#[unsafe(no_mangle)]
fn main() {
    // Create a init process
    axprocess::Process::new_init(axtask::current().id().as_u64() as _).build();
    
    // list_all_testcases();
    run_all_testcases();
    // run_single_testcase("/musl/runtest.exe -w entry-static.exe argv");
    // run_single_testcase("/musl/entry-static.exe argv");
}
