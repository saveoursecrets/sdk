//! UNIX timestamp that can be encoded to and from binary (12 bytes).
//!
//! Encoded as an i64 of the seconds since the UNIX epoch and
//! a u32 nanosecond offset from the second.

#[cfg(not(target_arch = "wasm32"))]
mod time;

#[cfg(not(target_arch = "wasm32"))]
pub use self::time::Timestamp;

#[cfg(target_arch = "wasm32")]
mod chrono;

#[cfg(target_arch = "wasm32")]
pub use self::chrono::Timestamp;

#[cfg(test)]
mod test {
    use anyhow::Result;
    use crate::{encode, decode};
    use super::Timestamp;

    #[test]
    fn timestamp_encode() -> Result<()> {
        let timestamp: Timestamp = Default::default();

        let buffer = encode(&timestamp)?;
        let timestamp: Timestamp = decode(&buffer)?;
        Ok(())
    }
}
