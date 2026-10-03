//! The hickory client: closed-loop load through `Resolver::lookup`.
//! Run with `--help`-style errors for the options; see the bench README.

use std::process::ExitCode;

use dns_lattice_bench_resolver::cli::client_main;
use dns_lattice_bench_resolver::hk::HkContestant;

fn main() -> ExitCode {
    client_main("hickory", HkContestant::new)
}
