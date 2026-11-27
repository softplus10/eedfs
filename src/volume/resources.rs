//! Mount-local accounting. No remote counter or extra publication is involved.
use super::{Error, Result};
use std::sync::{Arc, Mutex};
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub memory_bytes: u64,
    pub spool_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            memory_bytes: 512 * 1024 * 1024,
            spool_bytes: 4 * 1024 * 1024 * 1024,
        }
    }
}
struct State {
    limits: Limits,
    memory: u64,
    spool: u64,
}
pub struct Resources {
    state: Mutex<State>,
}
impl Default for Resources {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                limits: Limits::default(),
                memory: 0,
                spool: 0,
            }),
        }
    }
}
impl Resources {
    pub fn configure(&self, limits: Limits) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        if limits.memory_bytes == 0
            || limits.spool_bytes == 0
            || s.memory > limits.memory_bytes
            || s.spool > limits.spool_bytes
        {
            return Err(Error::Invalid);
        }
        s.limits = limits;
        Ok(())
    }
    pub fn memory(self: &Arc<Self>, bytes: u64) -> Result<Memory> {
        self.reserve(bytes, false)
    }
    pub fn work_memory(self: &Arc<Self>, bytes: u64) -> Result<Memory> {
        self.reserve(bytes, true)
    }
    fn reserve(self: &Arc<Self>, bytes: u64, work: bool) -> Result<Memory> {
        let mut s = self.state.lock().unwrap();
        let ceiling = if work {
            s.limits.memory_bytes
        } else {
            s.limits.memory_bytes - s.limits.memory_bytes / 4
        };
        if bytes > ceiling.saturating_sub(s.memory) {
            return Err(Error::NoMemory);
        }
        s.memory += bytes;
        Ok(Memory {
            resources: self.clone(),
            bytes,
        })
    }
    fn spool(&self, bytes: u64) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        if bytes > s.limits.spool_bytes.saturating_sub(s.spool) {
            return Err(Error::NoSpace);
        }
        s.spool += bytes;
        Ok(())
    }
    pub fn usage(&self) -> (u64, u64) {
        let s = self.state.lock().unwrap();
        (s.memory, s.spool)
    }
}
pub struct Memory {
    resources: Arc<Resources>,
    bytes: u64,
}
impl Memory {
    pub fn resize(&mut self, bytes: u64) -> Result<()> {
        if bytes > self.bytes {
            let mut extra = self.resources.memory(bytes - self.bytes)?;
            self.bytes = bytes;
            extra.bytes = 0;
        } else {
            self.resources.state.lock().unwrap().memory -= self.bytes - bytes;
            self.bytes = bytes;
        }
        Ok(())
    }
}
impl Drop for Memory {
    fn drop(&mut self) {
        self.resources.state.lock().unwrap().memory -= self.bytes;
    }
}
pub(super) struct Spool {
    resources: Arc<Resources>,
    ranges: Vec<(u64, u64)>,
    bytes: u64,
}
impl Spool {
    pub fn new(resources: Arc<Resources>) -> Self {
        Self {
            resources,
            ranges: vec![],
            bytes: 0,
        }
    }
    pub fn charge(&mut self, start: u64, end: u64) -> Result<()> {
        self.charge_many(&[(start, end)])
    }
    pub fn charge_many(&mut self, extra: &[(u64, u64)]) -> Result<()> {
        let block = 4096;
        let mut ranges = self.ranges.clone();
        for &(start, end) in extra {
            if start >= end {
                continue;
            }
            let start = start / block * block;
            let end = end.checked_add(block - 1).ok_or(Error::TooLarge)? / block * block;
            ranges.push((start, end));
        }
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = vec![];
        for (a, b) in ranges {
            if let Some(last) = merged.last_mut()
                && a <= last.1
            {
                last.1 = last.1.max(b);
            } else {
                merged.push((a, b));
            }
        }
        let bytes = merged.iter().map(|(a, b)| b - a).sum();
        self.resources.spool(bytes - self.bytes)?;
        self.ranges = merged;
        self.bytes = bytes;
        Ok(())
    }
    pub fn truncate(&mut self, size: u64) {
        let end = size.saturating_add(4095) / 4096 * 4096;
        let mut ranges = vec![];
        for &(a, b) in &self.ranges {
            if a < end {
                ranges.push((a, b.min(end)));
            }
        }
        let bytes = ranges.iter().map(|(a, b)| b - a).sum();
        self.resources.state.lock().unwrap().spool -= self.bytes - bytes;
        self.bytes = bytes;
        self.ranges = ranges;
    }
    pub fn clear(&mut self) {
        self.resources.state.lock().unwrap().spool -= self.bytes;
        self.bytes = 0;
        self.ranges.clear();
    }
}
impl Drop for Spool {
    fn drop(&mut self) {
        self.clear();
    }
}
