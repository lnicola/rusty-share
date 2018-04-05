use std::time::Duration;

pub trait DurationExt {
    fn to_millis(&self) -> u64;
}

impl DurationExt for Duration {
    fn to_millis(&self) -> u64 {
        1_000 * self.as_secs() + u64::from(self.subsec_nanos() + 500_000) / 1_000_000
    }
}
