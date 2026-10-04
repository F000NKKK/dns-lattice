//! Loopback smoke tests: the responder, both contestants and the load loop.
//!
//! Everything runs in-process on ephemeral loopback ports and asserts on
//! counts and outcomes, never on timing, so the tests are deterministic and
//! need no privileges. Cases that wait for a timeout use 200 ms.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use dns_lattice::upstream::PoolConfig;
use dns_lattice_bench_resolver::Proto;
use dns_lattice_bench_resolver::dl::{Connect, DlContestant};
use dns_lattice_bench_resolver::fixture::Fixture;
use dns_lattice_bench_resolver::hk::{self, HkContestant};
use dns_lattice_bench_resolver::loadgen::{
    Contestant, LoadSpec, NameMode, Outcome, Phase, closed_loop, prime,
};
use dns_lattice_bench_resolver::responder::{Responder, ResponderConfig, fetch_stats};
use dns_lattice_bench_resolver::wire::{self, Mix};
use tokio::net::UdpSocket;

const TIMEOUT: Duration = Duration::from_secs(2);

struct Env {
    responder: Responder,
    ca_der: Vec<u8>,
}

async fn start(config: ResponderConfig) -> Env {
    let fixture = Fixture::generate().expect("fixture");
    let responder = Responder::start(&fixture, config).await.expect("responder");
    Env {
        responder,
        ca_der: fixture.ca_der().to_vec(),
    }
}

impl Env {
    fn connect(&self, proto: Proto, timeout: Duration) -> Connect {
        Connect {
            proto,
            port: self.responder.ports().for_proto(proto),
            ca_der: self.ca_der.clone(),
            timeout,
        }
    }

    fn queries(&self, proto: Proto) -> u64 {
        self.responder.counters().snapshot(proto).queries
    }
}

async fn one<C: Contestant>(contestant: &C, mix: Mix, name: &str) -> Outcome {
    contestant
        .query(&contestant.prepare(&format!("{}-{name}.bench.test.", mix.as_str()), mix))
        .await
}

// ------------------------------------------------- one query per transport ---

#[tokio::test(flavor = "multi_thread")]
async fn dns_lattice_resolves_over_every_transport() {
    let env = start(ResponderConfig::default()).await;
    for proto in Proto::ALL {
        let contestant = DlContestant::new(&env.connect(proto, TIMEOUT)).unwrap();
        assert_eq!(
            one(&contestant, Mix::A, "0-1").await,
            Outcome::Ok,
            "{proto}"
        );
        assert_eq!(env.queries(proto), 1, "{proto}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hickory_resolves_over_every_transport() {
    let env = start(ResponderConfig::default()).await;
    for proto in Proto::ALL {
        let contestant = HkContestant::new(&env.connect(proto, TIMEOUT)).unwrap();
        assert_eq!(
            one(&contestant, Mix::A, "0-1").await,
            Outcome::Ok,
            "{proto}"
        );
        assert_eq!(env.queries(proto), 1, "{proto}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_mix_is_recognised_by_both_libraries() {
    let env = start(ResponderConfig::default()).await;
    // Over TCP so the 1.1 KB TXT answer is never truncated; UDP carries it
    // too because both libraries advertise a 1232-byte payload.
    for proto in [Proto::Udp, Proto::Tcp] {
        let dl = DlContestant::new(&env.connect(proto, TIMEOUT)).unwrap();
        let hk = HkContestant::new(&env.connect(proto, TIMEOUT)).unwrap();
        for mix in Mix::ALL {
            assert_eq!(one(&dl, mix, "0-1").await, Outcome::Ok, "dl {proto} {mix}");
            assert_eq!(one(&hk, mix, "0-1").await, Outcome::Ok, "hk {proto} {mix}");
        }
    }
    assert_eq!(env.responder.counters().snapshot(Proto::Udp).queries, 8);
    assert_eq!(
        env.responder
            .counters()
            .tc_replies
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "EDNS 1232 lets the TXT answer through over UDP"
    );
}

// ------------------------------------------------------ responder behavior ---

async fn raw_udp(env: &Env, payload: Option<u16>, mix: Mix) -> Vec<u8> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    socket
        .connect((Ipv4Addr::LOCALHOST, env.responder.ports().udp))
        .await
        .unwrap();
    let query = wire::encode_query(7, &mix.fqdn(0, 1), mix.qtype(), payload).unwrap();
    socket.send(&query).await.unwrap();
    let mut buf = vec![0_u8; 65_535];
    let len = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
        .await
        .expect("an answer arrives")
        .unwrap();
    buf.truncate(len);
    buf
}

fn flags(message: &[u8]) -> u16 {
    u16::from_be_bytes([message[2], message[3]])
}

fn count(message: &[u8], section: usize) -> u16 {
    u16::from_be_bytes([message[4 + 2 * section], message[5 + 2 * section]])
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_truncates_over_512_bytes_unless_edns_allows_more() {
    let env = start(ResponderConfig::default()).await;

    let plain = raw_udp(&env, None, Mix::Txt).await;
    assert_ne!(flags(&plain) & 0x0200, 0, "TC set without EDNS");
    assert_eq!(count(&plain, 1), 0, "a truncated answer carries no records");
    assert_eq!(count(&plain, 3), 0, "and no OPT without a query OPT");
    assert!(plain.len() <= 512);

    let edns = raw_udp(&env, Some(1232), Mix::Txt).await;
    assert_eq!(flags(&edns) & 0x0200, 0, "no TC with a 1232-byte payload");
    assert_eq!(count(&edns, 1), 1);
    assert_eq!(count(&edns, 3), 1, "the OPT is echoed");
    assert!(edns.len() > 512 && edns.len() <= 1232);

    assert_eq!(
        env.responder
            .counters()
            .tc_replies
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn nxdomain_carries_an_soa_and_opt_only_when_asked() {
    let env = start(ResponderConfig {
        ttl: 7,
        ..ResponderConfig::default()
    })
    .await;
    let plain = raw_udp(&env, None, Mix::Nx).await;
    assert_eq!(flags(&plain) & 0x000F, 3, "NXDOMAIN");
    assert_eq!(count(&plain, 1), 0);
    assert_eq!(count(&plain, 2), 1, "one SOA in the authority section");
    assert_eq!(
        count(&plain, 3),
        0,
        "no OPT in answer to a query without one"
    );
    let edns = raw_udp(&env, Some(1232), Mix::Nx).await;
    assert_eq!(count(&edns, 3), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_responder_adds_the_configured_latency() {
    let env = start(ResponderConfig {
        latency: Duration::from_millis(50),
        ..ResponderConfig::default()
    })
    .await;
    let contestant = DlContestant::new(&env.connect(Proto::Tcp, TIMEOUT)).unwrap();
    let began = std::time::Instant::now();
    assert_eq!(one(&contestant, Mix::A, "0-1").await, Outcome::Ok);
    // A lower bound only: a slow machine can take longer, never less.
    assert!(began.elapsed() >= Duration::from_millis(50));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_stats_port_reports_the_counters() {
    let env = start(ResponderConfig::default()).await;
    let contestant = DlContestant::new(&env.connect(Proto::Dot, TIMEOUT)).unwrap();
    assert_eq!(one(&contestant, Mix::A, "0-1").await, Outcome::Ok);
    let stats = fetch_stats(env.responder.ports().stats).await.unwrap();
    assert_eq!(stats["queries"], 1);
    assert_eq!(stats["transports"]["dot"]["queries"], 1);
    assert_eq!(stats["transports"]["dot"]["connections"], 1);
    assert_eq!(stats["transports"]["dot"]["handshakes"], 1);
    assert_eq!(stats["transports"]["udp"]["queries"], 0);
}

// ----------------------------------------------------- connection models ---

#[tokio::test(flavor = "multi_thread")]
async fn dns_lattice_pools_tcp_dot_doh2_and_doq_and_the_pool_can_be_disabled() {
    const QUERIES: u64 = 5;
    for proto in [Proto::Tcp, Proto::Dot, Proto::Doh2, Proto::Doq] {
        let env = start(ResponderConfig::default()).await;
        let dl = DlContestant::new(&env.connect(proto, TIMEOUT)).unwrap();
        for index in 0..QUERIES {
            assert_eq!(one(&dl, Mix::A, &format!("0-{index}")).await, Outcome::Ok);
        }
        let seen = env.responder.counters().snapshot(proto);
        assert_eq!(seen.queries, QUERIES, "dl {proto}");
        assert_eq!(seen.connections, 1, "dl {proto}: one pooled connection");

        // With the pool switched off the earlier model is still there.
        let env = start(ResponderConfig::default()).await;
        let dl =
            DlContestant::with_pool(&env.connect(proto, TIMEOUT), PoolConfig::disabled()).unwrap();
        for index in 0..QUERIES {
            assert_eq!(one(&dl, Mix::A, &format!("0-{index}")).await, Outcome::Ok);
        }
        let seen = env.responder.counters().snapshot(proto);
        assert_eq!(seen.queries, QUERIES, "dl {proto} unpooled");
        assert_eq!(
            seen.connections, QUERIES,
            "dl {proto} unpooled: one connection per query"
        );

        let env = start(ResponderConfig::default()).await;
        let hk = HkContestant::new(&env.connect(proto, TIMEOUT)).unwrap();
        for index in 0..QUERIES {
            assert_eq!(one(&hk, Mix::A, &format!("0-{index}")).await, Outcome::Ok);
        }
        let seen = env.responder.counters().snapshot(proto);
        assert_eq!(seen.queries, QUERIES, "hk {proto}");
        assert_eq!(seen.connections, 1, "hk {proto}: one pooled connection");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn handshakes_are_counted_per_encrypted_connection() {
    // Pooled: one connection, one handshake. Unpooled: a handshake per query.
    for (pool, handshakes) in [(PoolConfig::new(), 1), (PoolConfig::disabled(), 3)] {
        let env = start(ResponderConfig::default()).await;
        let dl = DlContestant::with_pool(&env.connect(Proto::Dot, TIMEOUT), pool).unwrap();
        for index in 0..3 {
            assert_eq!(one(&dl, Mix::A, &format!("0-{index}")).await, Outcome::Ok);
        }
        let seen = env.responder.counters().snapshot(Proto::Dot);
        assert_eq!(seen.handshakes, handshakes);
        assert!(seen.resumed <= seen.handshakes);
    }
}

// ---------------------------------------------------------- fairness knobs ---

#[tokio::test(flavor = "multi_thread")]
async fn hickory_attempts_zero_sends_exactly_one_query() {
    let timeout = Duration::from_millis(200);
    // The responder drops everything, so each lookup ends in a timeout and
    // the responder's counter shows how many times hickory tried.
    let env = start(ResponderConfig {
        drop_every: 1,
        ..ResponderConfig::default()
    })
    .await;
    let connect = env.connect(Proto::Udp, timeout);

    let fair = HkContestant::new(&connect).unwrap();
    assert_eq!(hk::ONE_ATTEMPT, 0);
    assert_eq!(fair.resolver().options().attempts, 0);
    assert_eq!(one(&fair, Mix::A, "0-1").await, Outcome::Timeout);
    assert_eq!(env.queries(Proto::Udp), 1, "attempts = 0: exactly one try");

    let retrying = HkContestant::with_options(&connect, |opts| opts.attempts = 1).unwrap();
    assert_eq!(one(&retrying, Mix::A, "0-2").await, Outcome::Timeout);
    assert_eq!(
        env.queries(Proto::Udp),
        3,
        "attempts = 1 sends a second query: it counts retries, not tries"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_lattice_sends_exactly_one_query_per_resolution() {
    let env = start(ResponderConfig {
        drop_every: 1,
        ..ResponderConfig::default()
    })
    .await;
    let dl = DlContestant::new(&env.connect(Proto::Udp, Duration::from_millis(200))).unwrap();
    assert_eq!(one(&dl, Mix::A, "0-1").await, Outcome::Timeout);
    assert_eq!(env.queries(Proto::Udp), 1);
}

async fn concurrent<C: Contestant>(contestant: Arc<C>, count: u32) -> Vec<Outcome> {
    let handles: Vec<_> = (0..count)
        .map(|index| {
            let contestant = contestant.clone();
            tokio::spawn(async move { one(&*contestant, Mix::A, &format!("0-{index}")).await })
        })
        .collect();
    let mut outcomes = Vec::new();
    for handle in handles {
        outcomes.push(handle.await.unwrap());
    }
    outcomes
}

#[tokio::test(flavor = "multi_thread")]
async fn hickory_with_the_harness_options_has_no_busy_errors_at_concurrency_256() {
    // The responder holds every answer for 100 ms, so all 256 lookups are
    // in flight at once on the one pooled DoT connection.
    let env = start(ResponderConfig {
        latency: Duration::from_millis(100),
        ..ResponderConfig::default()
    })
    .await;
    let connect = env.connect(Proto::Dot, TIMEOUT);

    // The real closed loop at concurrency 256, warm-up included, exactly as
    // the benchmark drives it.
    let fair = Arc::new(HkContestant::new(&connect).unwrap());
    assert_eq!(fair.resolver().options().max_active_requests, 256);
    let stats = closed_loop(
        fair,
        &LoadSpec {
            concurrency: 256,
            warmup: Duration::from_millis(300),
            duration: Duration::from_millis(700),
            mix: Mix::A,
            names_per_worker: 4,
            names: NameMode::Cold,
        },
        |_| {},
    )
    .await;
    assert!(stats.queries > 0);
    assert_eq!(
        stats.outcomes.errors.get("busy").copied().unwrap_or(0),
        0,
        "{:?}",
        stats.outcomes
    );
    assert_eq!(stats.outcomes.failures(), 0, "{:?}", stats.outcomes);
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_lattice_has_no_errors_at_concurrency_256() {
    let env = start(ResponderConfig {
        latency: Duration::from_millis(100),
        ..ResponderConfig::default()
    })
    .await;
    let dl = Arc::new(DlContestant::new(&env.connect(Proto::Dot, TIMEOUT)).unwrap());
    let outcomes = concurrent(dl, 256).await;
    assert!(
        outcomes.iter().all(|outcome| *outcome == Outcome::Ok),
        "{outcomes:?}"
    );
    assert_eq!(env.queries(Proto::Dot), 256);
}

// --------------------------------------------------------- the load loop ---

/// Records the names it is asked to prepare and answers instantly.
#[derive(Default)]
struct Recorder {
    prepared: Mutex<Vec<String>>,
}

impl Contestant for Recorder {
    type Prepared = ();

    fn prepare(&self, fqdn: &str, _mix: Mix) {
        self.prepared.lock().unwrap().push(fqdn.to_string());
    }

    async fn query(&self, _prepared: &()) -> Outcome {
        tokio::task::yield_now().await;
        Outcome::Ok
    }
}

fn spec(names: NameMode) -> LoadSpec {
    LoadSpec {
        concurrency: 3,
        warmup: Duration::from_millis(20),
        duration: Duration::from_millis(100),
        mix: Mix::Aaaa,
        names_per_worker: 4,
        names,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cold_workers_get_distinct_names_and_warm_workers_share_them() {
    let cold = Arc::new(Recorder::default());
    closed_loop(cold.clone(), &spec(NameMode::Cold), |_| {}).await;
    let mut names = cold.prepared.lock().unwrap().clone();
    assert_eq!(names.len(), 12);
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 12, "every cold name is distinct");
    assert!(names.contains(&"aaaa-2-3.bench.test.".to_string()));

    let warm = Arc::new(Recorder::default());
    closed_loop(warm.clone(), &spec(NameMode::Warm), |_| {}).await;
    let mut names = warm.prepared.lock().unwrap().clone();
    assert_eq!(names.len(), 12);
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 4, "warm workers share one rotation");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_load_loop_reports_phases_percentiles_and_outcomes() {
    let phases = Arc::new(Mutex::new(Vec::new()));
    let seen = phases.clone();
    let stats = closed_loop(
        Arc::new(Recorder::default()),
        &spec(NameMode::Cold),
        move |phase| seen.lock().unwrap().push(phase),
    )
    .await;
    assert_eq!(
        *phases.lock().unwrap(),
        vec![Phase::MeasureStart, Phase::MeasureEnd]
    );
    assert!(stats.queries > 0);
    assert_eq!(stats.outcomes.ok, stats.queries);
    assert_eq!(stats.outcomes.failures(), 0);
    assert!(stats.qps > 0.0);
    let lat = stats.lat_us;
    assert!(lat.p50 <= lat.p90 && lat.p90 <= lat.p99 && lat.p99 <= lat.p999 && lat.p999 <= lat.max);
}

#[tokio::test(flavor = "multi_thread")]
async fn priming_resolves_every_warm_name_once_and_reports_a_failure() {
    let recorder = Recorder::default();
    assert_eq!(prime(&recorder, &spec(NameMode::Warm)).await, None);
    assert_eq!(recorder.prepared.lock().unwrap().len(), 4);

    // Nothing answers: priming reports the first failed outcome.
    let env = start(ResponderConfig {
        drop_every: 1,
        ..ResponderConfig::default()
    })
    .await;
    let dl = DlContestant::new(&env.connect(Proto::Udp, Duration::from_millis(200))).unwrap();
    assert_eq!(
        prime(&dl, &spec(NameMode::Warm)).await,
        Some(Outcome::Timeout)
    );
}

// ------------------------------------------------ the client binaries ---

fn run_client(binary: &str, args: &[String]) -> (bool, serde_json::Value) {
    let output = std::process::Command::new(binary)
        .args(args)
        .output()
        .expect("client runs");
    let result = serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "client printed no JSON ({err}): {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.success(), result)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_binaries_report_a_valid_warm_run() {
    let env = start(ResponderConfig {
        ttl: 3600,
        ..ResponderConfig::default()
    })
    .await;
    let ca = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("smoke-ca.der");
    std::fs::write(&ca, &env.ca_der).unwrap();
    let ports = env.responder.ports();
    let args = |extra: &[&str]| -> Vec<String> {
        [
            "--proto",
            "tcp",
            "--port",
            &ports.tcp.to_string(),
            "--ca",
            ca.to_str().unwrap(),
            "--stats-port",
            &ports.stats.to_string(),
            "--concurrency",
            "4",
            "--warmup",
            "0.1",
            "--duration",
            "0.3",
            "--names",
            "8",
        ]
        .iter()
        .chain(extra)
        .map(|arg| (*arg).to_string())
        .collect()
    };

    for (binary, library) in [
        (env!("CARGO_BIN_EXE_dl-client"), "dns-lattice"),
        (env!("CARGO_BIN_EXE_hk-client"), "hickory"),
    ] {
        let warm = args(&["--cache", "warm"]);
        let (ok, result) = tokio::task::spawn_blocking(move || run_client(binary, &warm))
            .await
            .unwrap();
        assert!(ok, "{library}: {result}");
        assert_eq!(result["library"], library);
        assert_eq!(result["valid"], true, "{library}: {result}");
        assert_eq!(result["responder"]["queries"], 0, "{library}: all hits");
        assert!(result["stats"]["queries"].as_u64().unwrap() > 0);
        assert_eq!(
            result["stats"]["outcomes"]["ok"],
            result["stats"]["queries"]
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_warm_run_against_a_zero_ttl_responder_is_invalid() {
    let env = start(ResponderConfig::default()).await;
    let ca = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("smoke-ca-cold.der");
    std::fs::write(&ca, &env.ca_der).unwrap();
    let ports = env.responder.ports();
    let args: Vec<String> = [
        "--proto",
        "udp",
        "--port",
        &ports.udp.to_string(),
        "--ca",
        ca.to_str().unwrap(),
        "--stats-port",
        &ports.stats.to_string(),
        "--cache",
        "warm",
        "--concurrency",
        "2",
        "--warmup",
        "0.1",
        "--duration",
        "0.3",
        "--names",
        "4",
    ]
    .iter()
    .map(|arg| (*arg).to_string())
    .collect();
    let binary = env!("CARGO_BIN_EXE_dl-client");
    let (ok, result) = tokio::task::spawn_blocking(move || run_client(binary, &args))
        .await
        .unwrap();
    assert!(!ok);
    assert_eq!(result["valid"], false);
    assert!(
        result["invalid_reason"][0]
            .as_str()
            .unwrap()
            .contains("responder saw"),
        "{result}"
    );
}
