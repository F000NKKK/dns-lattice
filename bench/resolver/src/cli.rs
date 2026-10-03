//! Command-line handling shared by the harness binaries.
//!
//! Arguments are `--name value` or `--name=value` pairs, parsed by hand
//! (no `clap`), as in the other Lattice benchmark harnesses. [`client_main`]
//! is the whole body of the `dl-client` and `hk-client` binaries.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use crate::Proto;
use crate::dl::Connect;
use crate::loadgen::{Contestant, LoadSpec, NameMode, Phase, closed_loop, prime};
use crate::metrics::{self, ProcSample};
use crate::wire::Mix;

/// Parsed `--name value` arguments.
#[derive(Debug, Default)]
pub struct Args {
    values: BTreeMap<String, String>,
}

impl Args {
    /// Parses `--name value` and `--name=value` pairs.
    ///
    /// # Errors
    ///
    /// Returns a message for an argument that is not an option, an option
    /// without a value, or an option given twice.
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
        let mut values = BTreeMap::new();
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let Some(option) = arg.strip_prefix("--") else {
                return Err(format!("unexpected argument '{arg}'"));
            };
            let (name, value) = match option.split_once('=') {
                Some((name, value)) => (name.to_string(), value.to_string()),
                None => {
                    let value = args
                        .next()
                        .ok_or_else(|| format!("--{option} needs a value"))?;
                    (option.to_string(), value)
                }
            };
            if values.insert(name.clone(), value).is_some() {
                return Err(format!("--{name} given twice"));
            }
        }
        Ok(Args { values })
    }

    /// The value of `--name`, if given.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// The value of `--name`, or an error if it is missing.
    ///
    /// # Errors
    ///
    /// Returns a message naming the missing option.
    pub fn required(&self, name: &str) -> Result<&str, String> {
        self.get(name)
            .ok_or_else(|| format!("--{name} is required"))
    }

    /// The parsed value of `--name`, or `default` if it is not given.
    ///
    /// # Errors
    ///
    /// Returns a message if the value does not parse.
    pub fn parsed<T: FromStr>(&self, name: &str, default: T) -> Result<T, String> {
        match self.get(name) {
            None => Ok(default),
            Some(text) => text
                .parse()
                .map_err(|_| format!("--{name}: invalid value '{text}'")),
        }
    }

    /// Fails if any option other than `known` was given.
    ///
    /// # Errors
    ///
    /// Returns a message naming the first unknown option.
    pub fn only(&self, known: &[&str]) -> Result<(), String> {
        match self
            .values
            .keys()
            .find(|name| !known.contains(&name.as_str()))
        {
            Some(name) => Err(format!("unknown option --{name}")),
            None => Ok(()),
        }
    }
}

/// The options of `dl-client` and `hk-client`.
pub const CLIENT_USAGE: &str = "\
usage: <client> --proto udp|tcp|dot|doh2|doh3|doq --port PORT --ca FILE [options]
  --mix a|aaaa|txt|nx     query mix (default a)
  --concurrency N         closed-loop workers (default 16)
  --warmup SECONDS        warm-up, discarded (default 2)
  --duration SECONDS      measurement (default 8)
  --names N               names per worker rotation (default 1024)
  --cache cold|warm       cold: distinct names, TTL 0 upstream; warm: shared
                          names primed first, TTL 3600 upstream (default cold)
  --timeout-ms MS         per-query timeout, one attempt (default 2000)
  --workers N             runtime worker threads (default: available CPUs)
  --stats-port PORT       responder stats port: counters are recorded around
                          the measurement; a warm run is invalid if the
                          responder saw any query during it, and a cold run
                          is invalid if it saw fewer than the client completed
  --out FILE              write the JSON result there instead of stdout";

const CLIENT_OPTIONS: &[&str] = &[
    "proto",
    "port",
    "ca",
    "mix",
    "concurrency",
    "warmup",
    "duration",
    "names",
    "cache",
    "timeout-ms",
    "workers",
    "stats-port",
    "out",
];

/// The parsed options of a client binary.
#[derive(Debug)]
pub struct ClientArgs {
    /// The transport to resolve over.
    pub proto: Proto,
    /// The responder's port for `proto`.
    pub port: u16,
    /// Path of the fixture CA certificate (DER).
    pub ca: String,
    /// The query mix.
    pub mix: Mix,
    /// Closed-loop workers.
    pub concurrency: u32,
    /// Warm-up in seconds.
    pub warmup: f64,
    /// Measurement in seconds.
    pub duration: f64,
    /// Names per worker rotation.
    pub names: u32,
    /// Cold or warm names.
    pub cache: NameMode,
    /// Per-query timeout in milliseconds.
    pub timeout_ms: u64,
    /// Runtime worker threads.
    pub workers: usize,
    /// The responder's stats port, if counters should be recorded.
    pub stats_port: Option<u16>,
    /// Where to write the JSON result; stdout if `None`.
    pub out: Option<String>,
}

impl ClientArgs {
    /// Parses the command line of a client binary.
    ///
    /// # Errors
    ///
    /// Returns a message for a missing, unknown or invalid option.
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<ClientArgs, String> {
        let args = Args::parse(args)?;
        args.only(CLIENT_OPTIONS)?;
        let proto = args.required("proto")?;
        let mix = args.get("mix").unwrap_or("a");
        let cache = args.get("cache").unwrap_or("cold");
        let default_workers = std::thread::available_parallelism().map_or(1, usize::from);
        let parsed = ClientArgs {
            proto: Proto::parse(proto).ok_or_else(|| format!("--proto: unknown '{proto}'"))?,
            port: args
                .required("port")?
                .parse()
                .map_err(|_| "--port: invalid port".to_string())?,
            ca: args.required("ca")?.to_string(),
            mix: Mix::parse(mix).ok_or_else(|| format!("--mix: unknown '{mix}'"))?,
            concurrency: args.parsed("concurrency", 16)?,
            warmup: args.parsed("warmup", 2.0)?,
            duration: args.parsed("duration", 8.0)?,
            names: args.parsed("names", 1024)?,
            cache: NameMode::parse(cache).ok_or_else(|| format!("--cache: unknown '{cache}'"))?,
            timeout_ms: args.parsed("timeout-ms", 2000)?,
            workers: args.parsed("workers", default_workers)?,
            stats_port: match args.get("stats-port") {
                None => None,
                Some(text) => Some(
                    text.parse()
                        .map_err(|_| "--stats-port: invalid port".to_string())?,
                ),
            },
            out: args.get("out").map(str::to_string),
        };
        if parsed.concurrency == 0 || parsed.names == 0 || parsed.workers == 0 {
            return Err("--concurrency, --names and --workers must be at least 1".to_string());
        }
        if !(parsed.warmup >= 0.0 && parsed.duration > 0.0) {
            return Err("--warmup must be >= 0 and --duration > 0".to_string());
        }
        Ok(parsed)
    }
}

/// Reads the responder counters over its stats port, blocking; used from
/// the synchronous phase callback of the load loop.
fn fetch_stats_blocking(port: u16) -> Option<Value> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        Duration::from_secs(2),
    )
    .ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let mut text = String::new();
    stream.read_to_string(&mut text).ok()?;
    serde_json::from_str(&text).ok()
}

#[derive(Default)]
struct Marks {
    cpu: [Option<ProcSample>; 2],
    stats: [Option<Value>; 2],
}

fn counter(stats: &Option<Value>, proto: Proto, field: &str) -> Option<u64> {
    stats
        .as_ref()?
        .get("transports")?
        .get(proto.as_str())?
        .get(field)?
        .as_u64()
}

fn delta(marks: &Marks, proto: Proto, field: &str) -> Option<u64> {
    Some(counter(&marks.stats[1], proto, field)? - counter(&marks.stats[0], proto, field)?)
}

/// The whole body of a client binary: parse the command line, build the
/// contestant, run the closed-loop load and print the JSON result.
///
/// Exit code 0 for a valid run, 1 for an invalid run (still printed), 2 for
/// a failure to run, 64 for a usage error.
pub fn client_main<C, F>(library: &'static str, build: F) -> ExitCode
where
    C: Contestant,
    F: FnOnce(&Connect) -> Result<C, String>,
{
    let args = match ClientArgs::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{library}: {message}\n{CLIENT_USAGE}");
            return ExitCode::from(64);
        }
    };
    match run_client(library, &args, build) {
        Ok(result) => {
            let text = serde_json::to_string_pretty(&result).expect("JSON serializes");
            let valid = result["valid"].as_bool() == Some(true);
            match &args.out {
                Some(path) => {
                    if let Err(err) = std::fs::write(path, text + "\n") {
                        eprintln!("{library}: writing {path}: {err}");
                        return ExitCode::from(2);
                    }
                }
                None => println!("{text}"),
            }
            if valid {
                ExitCode::SUCCESS
            } else {
                eprintln!("{library}: invalid run: {}", result["invalid_reason"]);
                ExitCode::from(1)
            }
        }
        Err(message) => {
            eprintln!("{library}: {message}");
            ExitCode::from(2)
        }
    }
}

fn run_client<C, F>(library: &'static str, args: &ClientArgs, build: F) -> Result<Value, String>
where
    C: Contestant,
    F: FnOnce(&Connect) -> Result<C, String>,
{
    // A provider is installed explicitly so TLS never depends on feature
    // unification picking one.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let ca_der = std::fs::read(&args.ca).map_err(|e| format!("reading {}: {e}", args.ca))?;
    let connect = Connect {
        proto: args.proto,
        port: args.port,
        ca_der,
        timeout: Duration::from_millis(args.timeout_ms),
    };
    let spec = LoadSpec {
        concurrency: args.concurrency,
        warmup: Duration::from_secs_f64(args.warmup),
        duration: Duration::from_secs_f64(args.duration),
        mix: args.mix,
        names_per_worker: args.names,
        names: args.cache,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.workers)
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;

    let marks = Arc::new(Mutex::new(Marks::default()));
    let (stats, queries_primed) = runtime.block_on(async {
        let contestant = Arc::new(build(&connect)?);
        let mut primed = 0;
        if spec.names == NameMode::Warm {
            if let Some(outcome) = prime(&*contestant, &spec).await {
                return Err(format!("priming the cache failed: {outcome:?}"));
            }
            primed = u64::from(spec.names_per_worker);
        }
        let hook_marks = marks.clone();
        let stats_port = args.stats_port;
        let stats = closed_loop(contestant, &spec, move |phase| {
            let slot = usize::from(phase == Phase::MeasureEnd);
            let mut marks = hook_marks.lock().expect("marks lock");
            marks.cpu[slot] = metrics::sample(None);
            marks.stats[slot] = stats_port.and_then(fetch_stats_blocking);
        })
        .await;
        Ok::<_, String>((stats, primed))
    })?;

    let marks = marks.lock().expect("marks lock");
    let mut invalid = Vec::new();
    let mut result = json!({
        "library": library,
        "proto": args.proto.as_str(),
        "mix": args.mix.as_str(),
        "concurrency": args.concurrency,
        "cache": args.cache.as_str(),
        "warmup_s": args.warmup,
        "duration_s": args.duration,
        "names_per_worker": args.names,
        "timeout_ms": args.timeout_ms,
        "workers": args.workers,
        "primed": queries_primed,
        "stats": stats.to_json(),
    });

    if stats.queries == 0 {
        invalid.push("no query completed".to_string());
    }
    let failures = stats.outcomes.failures();
    if stats.queries > 0 && failures * 1000 > stats.queries {
        invalid.push(format!(
            "{failures} of {} queries failed (more than 0.1%)",
            stats.queries
        ));
    }
    if let [Some(start), Some(end)] = marks.cpu {
        let cpu_ms = end.cpu_ms_since(&start);
        result["cpu_ms"] = json!(cpu_ms);
        if stats.queries > 0 {
            result["cpu_ms_per_1k"] = json!(cpu_ms * 1000.0 / stats.queries as f64);
        }
        result["rss_kib_end"] = json!(end.rss_kib);
        result["peak_rss_kib"] = json!(end.peak_rss_kib);
    }
    if args.stats_port.is_some() {
        match delta(&marks, args.proto, "queries") {
            Some(upstream) => {
                let connections = delta(&marks, args.proto, "connections").unwrap_or(0);
                let handshakes = delta(&marks, args.proto, "handshakes").unwrap_or(0);
                let resumed = delta(&marks, args.proto, "resumed").unwrap_or(0);
                result["responder"] = json!({
                    "queries": upstream,
                    "connections": connections,
                    "handshakes": handshakes,
                    "resumed": resumed,
                    "connections_per_1k_queries": if stats.queries > 0 {
                        json!(connections as f64 * 1000.0 / stats.queries as f64)
                    } else {
                        Value::Null
                    },
                });
                if args.cache == NameMode::Warm && upstream > 0 {
                    invalid.push(format!(
                        "warm run: the responder saw {upstream} queries during the measurement"
                    ));
                }
                if let Some(reason) =
                    cold_shortfall(args.cache, upstream, stats.queries, args.concurrency)
                {
                    invalid.push(reason);
                }
            }
            None => invalid.push("the responder stats could not be read".to_string()),
        }
    } else if args.cache == NameMode::Warm {
        invalid.push("warm run without --stats-port cannot prove cache hits".to_string());
    }
    result["valid"] = json!(invalid.is_empty());
    result["invalid_reason"] = json!(invalid);
    Ok(result)
}

/// Validity rule for a cold run: every client query uses a fresh name, so
/// the responder must have seen at least as many queries as the client
/// completed. Fewer means some answers were served without reaching the
/// upstream (a cache or coalescing effect), so the row does not measure a
/// cold resolve. The window edges are not synchronized between the client
/// and the responder, so up to `concurrency` in-flight queries of slack are
/// tolerated. Returns the invalid reason, or `None` when the run is fine or
/// is not a cold run.
fn cold_shortfall(
    cache: NameMode,
    upstream: u64,
    client_queries: u64,
    concurrency: u32,
) -> Option<String> {
    if cache != NameMode::Cold {
        return None;
    }
    let slack = u64::from(concurrency);
    if upstream.saturating_add(slack) < client_queries {
        return Some(format!(
            "cold run: the responder saw {upstream} queries but the client completed \
             {client_queries}; some answers did not reach the upstream"
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cold_run_with_fewer_responder_queries_than_client_queries_is_invalid() {
        // Fewer upstream queries than completed client queries, beyond the
        // in-flight slack: invalid.
        let reason = cold_shortfall(NameMode::Cold, 900, 1000, 16).expect("invalid");
        assert!(reason.contains("900") && reason.contains("1000"));
        // Within the in-flight slack, equal, or more: valid.
        assert_eq!(cold_shortfall(NameMode::Cold, 990, 1000, 16), None);
        assert_eq!(cold_shortfall(NameMode::Cold, 1000, 1000, 16), None);
        assert_eq!(cold_shortfall(NameMode::Cold, 1200, 1000, 16), None);
        // A warm run is judged by its own rule, not this one.
        assert_eq!(cold_shortfall(NameMode::Warm, 0, 1000, 16), None);
    }

    fn parse(args: &[&str]) -> Result<ClientArgs, String> {
        ClientArgs::parse(args.iter().map(|arg| (*arg).to_string()))
    }

    #[test]
    fn options_accept_both_spellings_and_defaults() {
        let args = parse(&["--proto=doq", "--port", "853", "--ca", "ca.der"]).unwrap();
        assert_eq!(args.proto, Proto::Doq);
        assert_eq!(args.port, 853);
        assert_eq!(args.concurrency, 16);
        assert_eq!(args.cache, NameMode::Cold);
        assert_eq!(args.timeout_ms, 2000);
        assert_eq!(args.stats_port, None);
    }

    #[test]
    fn bad_options_are_rejected() {
        let base = ["--proto", "udp", "--port", "1", "--ca", "x"];
        assert!(parse(&[]).unwrap_err().contains("--proto"));
        assert!(parse(&["--proto", "sctp", "--port", "1", "--ca", "x"]).is_err());
        assert!(parse(&[&base[..], &["--mix", "mx"]].concat()).is_err());
        assert!(parse(&[&base[..], &["--cache", "hot"]].concat()).is_err());
        assert!(parse(&[&base[..], &["--bogus", "1"]].concat()).is_err());
        assert!(parse(&[&base[..], &["--concurrency", "0"]].concat()).is_err());
        assert!(parse(&[&base[..], &["--duration", "0"]].concat()).is_err());
        assert!(parse(&[&base[..], &["--port", "2"]].concat()).is_err());
        assert!(parse(&["--proto"]).is_err());
        assert!(parse(&["udp"]).is_err());
    }
}
