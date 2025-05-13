#![no_std]
#![no_main]
#![doc = include_str!("../README.md")]

#[macro_use]
extern crate axlog;
extern crate alloc;

mod entry;
mod mm;
mod syscall;

use alloc::vec::Vec;

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

    // let testcases = option_env!("AX_TESTCASES_LIST")
    // .unwrap_or_else(|| "Please specify the testcases list by making user_apps")
    // .split(',')
    // .filter(|&x| !x.is_empty());

    // for testcase in testcases {
    //     let Some(args) = shlex::split(testcase) else {
    //         error!("Failed to parse testcase: {:?}", testcase);
    //         continue;
    //     };
    //     if args.is_empty() {
    //         continue;
    //     }
    //     error!("Running user task: {:?}", args);
    //     let exit_code = entry::run_user_app(&args, &[]);
    //     error!("User task {:?} exited with code: {:?}", args, exit_code);
    // }
    
    list_all_testcases();
    run_all_testcases();
    
    // run_single_testcase("test_pipe");
    // run_single_testcase("/musl/entry-static.exe fscanf ");



    // run_single_testcase("/musl/entry-static.exe fscanf");
    // run_single_testcase("/musl/entry-static.exe argv");
}
