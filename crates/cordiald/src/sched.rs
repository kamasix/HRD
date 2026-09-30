//! Deciding whether another start may begin now.
//!
//! A start is the expensive moment of a client's life (decompression,
//! relocation, asset loading, first round trips) and on a small machine the
//! cost lands on every client already running. The decision is a pure function
//! of facts the supervisor gathered, so it can be reasoned about and tested.

use hrd_core::config::SchedulerCfg;

const MIB: u64 = 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct Estimator {
    observed: std::collections::VecDeque<u64>,
}

impl Estimator {
    pub fn record(&mut self, peak_bytes: u64) {
        if peak_bytes == 0 {
            return;
        }
        if self.observed.len() == 8 {
            self.observed.pop_front();
        }
        self.observed.push_back(peak_bytes);
    }

    pub fn samples(&self) -> usize {
        self.observed.len()
    }

    /// What one more start is expected to add, in bytes. Until three starts
    /// have been measured the configured guess is the floor; afterwards the
    /// largest recent observation plus about 14 %. The value is an estimate of a
    /// peak, and says nothing about steady-state cost.
    pub fn estimate(&self, assumed_mib: u64) -> u64 {
        let assumed = assumed_mib.saturating_mul(MIB);
        let max = self.observed.iter().copied().max().unwrap_or(0);
        if self.observed.len() >= 3 {
            (max + max / 7).max(assumed / 4)
        } else {
            assumed.max(max)
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub mem_available: Option<u64>,
    pub mem_pressure_avg10: Option<f64>,
    pub cpu_pressure_avg10: Option<f64>,
    /// Starts that have not finished.
    pub in_flight: u32,
    /// Bytes those starts are still expected to add (estimate minus what they
    /// already hold).
    pub reserved: u64,
    pub live_total: u32,
    pub since_last_start_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Start,
    Wait(String),
}

pub fn decide(cfg: &SchedulerCfg, concurrency: u32, est_bytes: u64, f: &Facts) -> Verdict {
    if f.live_total >= cfg.max_instances {
        return Verdict::Wait(format!(
            "{} instances are live, the configured maximum",
            f.live_total
        ));
    }
    if f.in_flight >= concurrency {
        return Verdict::Wait(format!(
            "{} start(s) in flight, the limit is {concurrency}",
            f.in_flight
        ));
    }
    if f.in_flight > 0 && f.since_last_start_ms < cfg.min_start_interval_ms {
        return Verdict::Wait("waiting out the minimum interval between starts".into());
    }
    if let Some(avail) = f.mem_available {
        let need = est_bytes + f.reserved + cfg.min_available_mem_mib * MIB;
        if avail < need {
            return Verdict::Wait(format!(
                "memory: {} MiB available, a start needs about {} MiB plus {} MiB kept free",
                avail / MIB,
                (est_bytes + f.reserved) / MIB,
                cfg.min_available_mem_mib
            ));
        }
    }
    if cfg.max_memory_pressure_avg10 > 0.0 {
        if let Some(p) = f.mem_pressure_avg10 {
            if p > cfg.max_memory_pressure_avg10 {
                return Verdict::Wait(format!(
                    "memory pressure {p:.1}% is above {:.1}%",
                    cfg.max_memory_pressure_avg10
                ));
            }
        }
    }
    if cfg.max_cpu_pressure_avg10 > 0.0 {
        if let Some(p) = f.cpu_pressure_avg10 {
            if p > cfg.max_cpu_pressure_avg10 {
                return Verdict::Wait(format!(
                    "cpu pressure {p:.1}% is above {:.1}%",
                    cfg.max_cpu_pressure_avg10
                ));
            }
        }
    }
    Verdict::Start
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SchedulerCfg {
        SchedulerCfg::default()
    }
    fn roomy() -> Facts {
        Facts {
            mem_available: Some(64 * 1024 * MIB),
            ..Default::default()
        }
    }

    #[test]
    fn a_roomy_idle_machine_starts() {
        assert_eq!(decide(&cfg(), 2, 1536 * MIB, &roomy()), Verdict::Start);
    }

    #[test]
    fn concurrency_and_interval_hold_starts_back() {
        let mut f = roomy();
        f.in_flight = 2;
        assert!(matches!(decide(&cfg(), 2, 0, &f), Verdict::Wait(_)));
        f.in_flight = 1;
        f.since_last_start_ms = 100;
        assert!(matches!(decide(&cfg(), 2, 0, &f), Verdict::Wait(m) if m.contains("interval")));
        f.since_last_start_ms = 10_000;
        assert_eq!(decide(&cfg(), 2, 0, &f), Verdict::Start);
    }

    #[test]
    fn memory_counts_what_starts_in_flight_have_yet_to_take() {
        let mut f = Facts {
            mem_available: Some(6 * 1024 * MIB),
            ..Default::default()
        };
        assert_eq!(decide(&cfg(), 4, 1536 * MIB, &f), Verdict::Start);
        f.in_flight = 1;
        f.since_last_start_ms = 10_000;
        f.reserved = 3 * 1024 * MIB;
        // 6144 available < 1536 + 3072 + 2048 kept free? 6656 needed.
        assert!(
            matches!(decide(&cfg(), 4, 1536 * MIB, &f), Verdict::Wait(m) if m.contains("memory"))
        );
    }

    #[test]
    fn pressure_defers_and_zero_disables() {
        let mut f = roomy();
        f.mem_pressure_avg10 = Some(50.0);
        assert!(matches!(decide(&cfg(), 2, 0, &f), Verdict::Wait(_)));
        let mut c = cfg();
        c.max_memory_pressure_avg10 = 0.0;
        assert_eq!(decide(&c, 2, 0, &f), Verdict::Start);
        f.cpu_pressure_avg10 = Some(99.0);
        assert!(matches!(decide(&c, 2, 0, &f), Verdict::Wait(m) if m.contains("cpu")));
    }

    #[test]
    fn the_instance_ceiling_is_enforced() {
        let mut f = roomy();
        f.live_total = cfg().max_instances;
        assert!(matches!(decide(&cfg(), 2, 0, &f), Verdict::Wait(_)));
    }

    #[test]
    fn unknown_memory_does_not_block_but_is_not_assumed_plentiful() {
        // Unmeasurable: decide on the other facts, never invent a number.
        let f = Facts::default();
        assert_eq!(decide(&cfg(), 2, 1536 * MIB, &f), Verdict::Start);
    }

    #[test]
    fn the_estimate_starts_as_the_guess_then_follows_measurements() {
        let mut e = Estimator::default();
        assert_eq!(e.estimate(1536), 1536 * MIB);
        e.record(900 * MIB);
        assert_eq!(e.estimate(1536), 1536 * MIB);
        e.record(1000 * MIB);
        e.record(950 * MIB);
        let est = e.estimate(1536);
        assert!(est > 1000 * MIB && est < 1200 * MIB, "{est}");
        e.record(0);
        assert_eq!(e.samples(), 3);
    }
}
