// A direction's buffer sizes, Linux's tcp_wmem/tcp_rmem triple, and an
// endpoint's buffer configuration as the three sysctls print it.
use crate::{BufferMemory, Error};
use core::fmt;

/// One direction's buffer sizes in bytes, Linux's tcp_wmem or tcp_rmem
/// triple: `min` is the floor memory pressure leaves (tcp_wmem[0]), `initial`
/// the size a connection opens with (tcp_wmem[1]) and `max` the ceiling
/// autotuning grows to (tcp_wmem[2]). A direction is tuned when `max`
/// exceeds `initial`. Displays as `"min initial max"`, as the sysctl prints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferSizes {
    pub min: usize,
    pub initial: usize,
    pub max: usize,
}

impl BufferSizes {
    // 1 ≤ min ≤ initial ≤ max ≤ `limit`.
    pub(crate) fn validate(self, limit: usize) -> Result<(), Error> {
        if self.min == 0 || self.min > self.initial || self.initial > self.max || self.max > limit {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl fmt::Display for BufferSizes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.min, self.initial, self.max)
    }
}

/// An endpoint's buffer configuration (`EndpointConfig::buffers`): the send
/// and receive sizes and the memory thresholds, Linux's tcp_wmem, tcp_rmem
/// and tcp_mem. Displays as `"wmem=… rmem=… mem=…"`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Buffers {
    pub send: BufferSizes,
    pub receive: BufferSizes,
    pub memory: BufferMemory,
}

impl fmt::Display for Buffers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "wmem={} rmem={} mem={}",
            self.send, self.receive, self.memory
        )
    }
}
