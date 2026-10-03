//! The benchmark upstream: UDP, TCP, DoT, DoH2, DoH3 and DoQ on loopback.
//!
//! Prints one JSON line to stdout when ready (ports, pid and the CA file),
//! then serves until stdin reaches end-of-file or the process receives
//! SIGINT or SIGTERM. On the way out it writes the final counters to
//! `--out`.

use std::process::ExitCode;
use std::time::Duration;

use dns_lattice_bench_resolver::cli::Args;
use dns_lattice_bench_resolver::fixture::Fixture;
use dns_lattice_bench_resolver::responder::{Responder, ResponderConfig};
use serde_json::json;
use tokio::io::AsyncReadExt;

/// SIGTERM on Unix; never fires elsewhere (Ctrl-C and stdin end-of-file
/// still stop the responder).
struct Terminate {
    #[cfg(unix)]
    signal: tokio::signal::unix::Signal,
}

impl Terminate {
    fn new() -> Result<Self, String> {
        Ok(Self {
            #[cfg(unix)]
            signal: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|e| e.to_string())?,
        })
    }

    async fn recv(&mut self) {
        #[cfg(unix)]
        {
            self.signal.recv().await;
        }
        #[cfg(not(unix))]
        {
            std::future::pending::<()>().await;
        }
    }
}

const USAGE: &str = "\
usage: responder --ca-out FILE [options]
  --ca-out FILE        write the fixture CA certificate (DER) there
  --ttl SECONDS        TTL of every record, and the SOA minimum (default 0)
  --latency-us MICROS  delay before every answer (default 0)
  --drop-every N       leave every N-th query unanswered; 1 drops all
                       (default 0: none)
  --out FILE           write the final counters there on exit";

fn main() -> ExitCode {
    let args = match Args::parse(std::env::args().skip(1)).and_then(|args| {
        args.only(&["ca-out", "ttl", "latency-us", "drop-every", "out"])?;
        Ok(args)
    }) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("responder: {message}\n{USAGE}");
            return ExitCode::from(64);
        }
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("responder: {message}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &Args) -> Result<(), String> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let config = ResponderConfig {
        ttl: args.parsed("ttl", 0)?,
        latency: Duration::from_micros(args.parsed("latency-us", 0)?),
        drop_every: args.parsed("drop-every", 0)?,
    };
    let ca_out = args.required("ca-out")?.to_string();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    runtime.block_on(async {
        let fixture = Fixture::generate().map_err(|e| e.to_string())?;
        std::fs::write(&ca_out, fixture.ca_der()).map_err(|e| format!("writing {ca_out}: {e}"))?;
        let responder = Responder::start(&fixture, config)
            .await
            .map_err(|e| format!("starting: {e}"))?;
        let ready = json!({
            "ports": responder.ports().to_json(),
            "pid": std::process::id(),
            "ca": ca_out,
        });
        println!("{ready}");

        let mut terminate = Terminate::new()?;
        let mut stdin = tokio::io::stdin();
        let mut sink = [0_u8; 256];
        loop {
            tokio::select! {
                () = terminate.recv() => break,
                _ = tokio::signal::ctrl_c() => break,
                read = stdin.read(&mut sink) => {
                    if matches!(read, Ok(0) | Err(_)) {
                        break;
                    }
                }
            }
        }
        responder.shutdown();
        if let Some(path) = args.get("out") {
            let text = serde_json::to_string_pretty(&responder.counters().to_json())
                .expect("JSON serializes");
            std::fs::write(path, text + "\n").map_err(|e| format!("writing {path}: {e}"))?;
        }
        Ok(())
    })
}
