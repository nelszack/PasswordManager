//! Opt-in benchmark support shared by the library and desktop test harnesses.
//! Fixtures and warmup are excluded; output destruction is included in timings.
use std::{hint::black_box, io::Write, time::Instant};

pub(crate) struct Config {
    pub sizes: Vec<usize>,
    samples: usize,
    sample_ns: f64,
}
impl Config {
    pub fn read() -> Self {
        fn number(name: &str, default: usize, min: usize, max: usize) -> usize {
            let value = std::env::var(name)
                .map_or(default, |v| v.parse().expect("invalid benchmark number"));
            assert!((min..=max).contains(&value), "invalid {name}");
            value
        }
        let sizes = std::env::var("PM_BENCH_SIZES")
            .unwrap_or_else(|_| "100,1000,10000".into())
            .split(',')
            .map(|value| {
                let value = value.parse::<usize>().expect("invalid benchmark size");
                assert!(
                    (1..=100_000).contains(&value),
                    "benchmark size out of range"
                );
                value
            })
            .collect();
        Self {
            sizes,
            samples: number("PM_BENCH_SAMPLES", 9, 3, 100),
            sample_ns: number("PM_BENCH_SAMPLE_MS", 20, 1, 1000) as f64 * 1_000_000.0,
        }
    }
    pub fn measure<S, R>(
        &self,
        suite: &str,
        name: &str,
        size: usize,
        mut setup: impl FnMut() -> S,
        mut operation: impl FnMut(&mut S) -> R,
    ) {
        // Fresh setup for each operation lets cold-cache cases exclude fixture
        // construction. Warm cases capture a prewarmed fixture and use () setup.
        let mut once = || {
            let mut state = setup();
            let start = Instant::now();
            drop(black_box(operation(black_box(&mut state))));
            start.elapsed().as_nanos().max(1) as f64
        };
        let calibration = (0..3).map(|_| once()).sum::<f64>() / 3.0;
        let iterations = (self.sample_ns / calibration).ceil().clamp(1.0, 1000.0) as usize;
        let mut samples: Vec<f64> = (0..self.samples)
            .map(|_| (0..iterations).map(|_| once()).sum::<f64>() / iterations as f64)
            .collect();
        let sample_order = samples.clone();
        samples.sort_by(f64::total_cmp);
        let record = serde_json::json!({
            "schema_version": 1, "suite": suite, "name": name, "size": size,
            "unit": "ns/op", "samples": self.samples, "iterations_per_sample": iterations,
            "median_ns": (samples[(samples.len()-1)/2] + samples[samples.len()/2]) / 2.0,
            "p95_ns": samples[(samples.len()*95).div_ceil(100).saturating_sub(1)],
            "min_ns": samples[0], "sample_means_ns": sample_order,
            "optimized": !cfg!(debug_assertions),
        });
        println!("BENCH {}", record);
        if let Ok(path) = std::env::var("PM_BENCH_OUTPUT") {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .expect("benchmark output");
            writeln!(file, "{record}").expect("write benchmark output");
        }
    }
}
