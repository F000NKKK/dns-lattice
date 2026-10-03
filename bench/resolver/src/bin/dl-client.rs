//! The dns-lattice client: closed-loop load through `Resolver::resolve`.
//! Run with `--help`-style errors for the options; see the bench README.

use std::process::ExitCode;

use dns_lattice_bench_resolver::cli::client_main;
use dns_lattice_bench_resolver::dl::DlContestant;

fn main() -> ExitCode {
    client_main("dns-lattice", DlContestant::new)
}
