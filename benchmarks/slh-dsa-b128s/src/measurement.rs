//! Adapted from `crates/pq-bench-support/src/lib.rs` at research commit
//! 53a6e4bd1c11d90349fd3d989507f0e1a4995112 (MIT OR Apache-2.0).
//!
//! The OS observation sequence and units are retained. This local subset omits
//! the allocator and statistics. OS errors are explicit unavailable metrics.
//! Endpoint RSS is not an interval peak; the high-water mark includes all setup
//! and earlier attempts in this process. CPU boundaries include timer overhead.

use std::{hint::black_box, mem::MaybeUninit, time::Instant};

use serde_json::{Map, Value};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("tpq-bench OS observations currently support Linux and macOS only");

pub struct Observation {
    pub metrics: Map<String, Value>,
    pub unavailable: Map<String, Value>,
}

impl Observation {
    fn insert(&mut self, name: &str, value: Result<u64, String>) {
        match value {
            Ok(value) => {
                self.metrics.insert(name.into(), value.into());
            }
            Err(reason) => {
                self.metrics.insert(name.into(), Value::Null);
                self.unavailable.insert(name.into(), reason.into());
            }
        }
    }
}

fn usage() -> Result<libc::rusage, String> {
    let mut result = MaybeUninit::uninit();
    // SAFETY: getrusage receives a correctly sized, aligned output buffer. The
    // buffer is read only when the OS reports successful initialization.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, result.as_mut_ptr()) } != 0 {
        return Err(format!(
            "getrusage failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful getrusage initialized the complete buffer above.
    Ok(unsafe { result.assume_init() })
}

fn timeval_ns(value: libc::timeval) -> Result<u64, String> {
    let seconds = u64::try_from(value.tv_sec).map_err(|_| "negative process CPU seconds")?;
    let micros = u64::try_from(value.tv_usec).map_err(|_| "negative process CPU microseconds")?;
    if micros >= 1_000_000 {
        return Err("process CPU microseconds are out of range".into());
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(micros * 1_000))
        .ok_or_else(|| "process CPU nanosecond conversion overflowed".into())
}

fn cpu_ns(usage: &libc::rusage) -> Result<u64, String> {
    timeval_ns(usage.ru_utime)?
        .checked_add(timeval_ns(usage.ru_stime)?)
        .ok_or_else(|| "process CPU counter overflowed".into())
}

fn peak_rss_bytes(usage: &libc::rusage) -> Result<u64, String> {
    let value = u64::try_from(usage.ru_maxrss).map_err(|_| "negative process peak RSS")?;
    let units = if cfg!(target_os = "macos") { 1 } else { 1024 };
    value
        .checked_mul(units)
        .ok_or_else(|| "process peak RSS conversion overflowed".into())
}

#[cfg(target_os = "macos")]
fn resident_bytes() -> Result<u64, String> {
    let mut result = MaybeUninit::<libc::rusage_info_v2>::uninit();
    // SAFETY: the V2 flavor writes exactly rusage_info_v2 to this aligned buffer.
    // getpid has no preconditions. The buffer is read only after OS success.
    let status = unsafe {
        libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V2,
            result.as_mut_ptr().cast(),
        )
    };
    if status != 0 {
        return Err(format!(
            "proc_pid_rusage failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful proc_pid_rusage initialized the V2 buffer above.
    Ok(unsafe { result.assume_init() }.ri_resident_size)
}

#[cfg(target_os = "linux")]
fn resident_bytes() -> Result<u64, String> {
    let contents = std::fs::read_to_string("/proc/self/statm")
        .map_err(|error| format!("cannot read /proc/self/statm: {error}"))?;
    // SAFETY: sysconf reads the page-size constant and takes no pointer arguments.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    statm_resident_bytes(&contents, page_size)
}

#[cfg(any(target_os = "linux", test))]
fn statm_resident_bytes(contents: &str, page_size: libc::c_long) -> Result<u64, String> {
    let pages: u64 = contents
        .split_whitespace()
        .nth(1)
        .ok_or("resident-page count missing from /proc/self/statm")?
        .parse()
        .map_err(|_| "invalid resident-page count in /proc/self/statm")?;
    let page_size = u64::try_from(page_size)
        .ok()
        .filter(|size| *size != 0)
        .ok_or("sysconf returned no positive page size")?;
    pages
        .checked_mul(page_size)
        .ok_or_else(|| "resident byte conversion overflowed".into())
}

pub fn observe<T>(timing_metric: &str, operation: impl FnOnce() -> T) -> (T, Observation) {
    let rss_before = resident_bytes();
    let before = usage();
    let started = Instant::now();
    let output = black_box(operation());
    let elapsed = u64::try_from(started.elapsed().as_nanos())
        .map_err(|_| "monotonic elapsed nanoseconds overflowed".into());
    let after = usage();
    let rss_after = resident_bytes();

    let process_cpu = (|| {
        let before = cpu_ns(before.as_ref().map_err(Clone::clone)?)?;
        let after = cpu_ns(after.as_ref().map_err(Clone::clone)?)?;
        after
            .checked_sub(before)
            .ok_or_else(|| "process CPU counter moved backwards".into())
    })();
    let peak_rss = after
        .as_ref()
        .map_err(Clone::clone)
        .and_then(peak_rss_bytes);
    let mut observation = Observation {
        metrics: Map::new(),
        unavailable: Map::new(),
    };
    observation.insert("attempt_elapsed_ns", elapsed.clone());
    observation.insert(timing_metric, elapsed.clone());
    observation.insert("process_cpu_ns", process_cpu.clone());
    observation.insert("rss_before_bytes", rss_before);
    observation.insert("rss_after_bytes", rss_after);
    observation.insert("process_peak_rss_bytes", peak_rss);
    match (process_cpu, elapsed) {
        (Ok(cpu), Ok(wall)) if wall != 0 => {
            // The bounded nanosecond counters fit finite f64 values. Precision
            // loss in this derived ratio does not alter the integer observations.
            let cores = cpu as f64 / wall as f64;
            observation
                .metrics
                .insert("process_cpu_core_equivalents".into(), cores.into());
        }
        _ => {
            observation
                .metrics
                .insert("process_cpu_core_equivalents".into(), Value::Null);
            observation.unavailable.insert(
                "process_cpu_core_equivalents".into(),
                "requires available process CPU and positive elapsed nanoseconds".into(),
            );
        }
    }
    (output, observation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_usage() -> libc::rusage {
        // SAFETY: rusage consists of integer fields whose all-zero value is valid.
        unsafe { MaybeUninit::zeroed().assume_init() }
    }

    #[test]
    fn cpu_and_rss_units_are_explicit() {
        let mut usage = synthetic_usage();
        usage.ru_utime.tv_sec = 2;
        usage.ru_utime.tv_usec = 345;
        usage.ru_stime.tv_sec = 1;
        usage.ru_stime.tv_usec = 678;
        usage.ru_maxrss = 123;
        assert_eq!(cpu_ns(&usage), Ok(3_001_023_000));
        assert_eq!(
            peak_rss_bytes(&usage),
            Ok(if cfg!(target_os = "macos") {
                123
            } else {
                125_952
            })
        );
        assert_eq!(statm_resident_bytes("100 3 2 1", 4096), Ok(12_288));
    }

    #[test]
    fn malformed_and_overflowing_os_counters_are_unavailable_not_zero() {
        let mut usage = synthetic_usage();
        usage.ru_utime.tv_usec = -1;
        assert!(cpu_ns(&usage).is_err());
        usage.ru_utime.tv_usec = 1_000_000;
        assert!(cpu_ns(&usage).is_err());
        usage.ru_maxrss = -1;
        assert!(peak_rss_bytes(&usage).is_err());
        assert!(statm_resident_bytes("100", 4096).is_err());
        assert!(statm_resident_bytes("100 invalid", 4096).is_err());
        assert!(statm_resident_bytes("100 3", -1).is_err());
        assert!(statm_resident_bytes("100 3", 0).is_err());
        assert!(statm_resident_bytes("100 18446744073709551615", 4096).is_err());
        let mut observation = Observation {
            metrics: Map::new(),
            unavailable: Map::new(),
        };
        observation.insert("rss_after_bytes", Err("OS query failed".into()));
        assert!(observation.metrics["rss_after_bytes"].is_null());
        assert_eq!(
            observation.unavailable["rss_after_bytes"],
            "OS query failed"
        );
    }
}
