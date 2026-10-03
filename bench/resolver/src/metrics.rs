//! Process CPU and memory samples.
//!
//! Read from Linux `/proc`; on other platforms [`sample`] returns `None`
//! and the benchmark runs without CPU and memory columns.

use serde_json::{Value, json};

/// Kernel clock ticks per second (`USER_HZ`), fixed at 100 on every Linux
/// architecture Rust supports; avoids a `libc` dependency for `sysconf`.
pub const TICKS_PER_SECOND: u64 = 100;

/// A sample of one process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcSample {
    /// User plus system CPU time consumed so far, in clock ticks.
    pub cpu_ticks: u64,
    /// Resident set size now, in KiB.
    pub rss_kib: u64,
    /// Peak resident set size, in KiB.
    pub peak_rss_kib: u64,
}

impl ProcSample {
    /// CPU milliseconds consumed between `earlier` and `self`.
    pub fn cpu_ms_since(&self, earlier: &ProcSample) -> f64 {
        self.cpu_ticks.saturating_sub(earlier.cpu_ticks) as f64 * 1000.0 / TICKS_PER_SECOND as f64
    }

    /// The sample as a JSON object.
    pub fn to_json(&self) -> Value {
        json!({
            "cpu_ticks": self.cpu_ticks,
            "rss_kib": self.rss_kib,
            "peak_rss_kib": self.peak_rss_kib,
        })
    }
}

/// Samples the process `pid`, or the current process for `None`.
pub fn sample(pid: Option<u32>) -> Option<ProcSample> {
    let dir = match pid {
        Some(pid) => format!("/proc/{pid}"),
        None => "/proc/self".to_string(),
    };
    let stat = std::fs::read_to_string(format!("{dir}/stat")).ok()?;
    let status = std::fs::read_to_string(format!("{dir}/status")).ok()?;
    Some(ProcSample {
        cpu_ticks: parse_cpu_ticks(&stat)?,
        rss_kib: parse_kib(&status, "VmRSS:")?,
        peak_rss_kib: parse_kib(&status, "VmHWM:")?,
    })
}

/// `utime + stime` from the contents of `/proc/<pid>/stat`. The command
/// name (field 2) may contain spaces and parentheses, so fields are counted
/// from the last `)`.
fn parse_cpu_ticks(stat: &str) -> Option<u64> {
    let after_comm = &stat[stat.rfind(')')? + 1..];
    let mut fields = after_comm.split_whitespace();
    // Field 3 (state) is the first one after the command name; utime and
    // stime are fields 14 and 15.
    let utime: u64 = fields.nth(11)?.parse().ok()?;
    let stime: u64 = fields.next()?.parse().ok()?;
    Some(utime + stime)
}

fn parse_kib(status: &str, key: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_ticks_survive_a_command_name_with_spaces_and_parentheses() {
        let stat = "1234 (a b) c) S 1 2 3 4 5 6 7 8 9 10 111 222 13 14 15";
        assert_eq!(parse_cpu_ticks(stat), Some(333));
    }

    #[test]
    fn kib_values_are_read_by_key() {
        let status = "Name:\tx\nVmHWM:\t  2048 kB\nVmRSS:\t  1024 kB\n";
        assert_eq!(parse_kib(status, "VmRSS:"), Some(1024));
        assert_eq!(parse_kib(status, "VmHWM:"), Some(2048));
        assert_eq!(parse_kib(status, "VmSwap:"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_current_process_can_be_sampled() {
        let sample = sample(None).expect("/proc is readable");
        assert!(sample.rss_kib > 0);
        assert!(sample.peak_rss_kib >= sample.rss_kib);
    }
}
