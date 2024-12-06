//! Compression functions configured for smallest size compression.
//!
//! Smallest size is chosen as these functions are used for the local
//! client and server communicate via the Native Messaging API for the
//! browser extension; the limit for a single message is 1MB so we
//! need them to be as small as possible.

#[cfg(feature = "compression-zlib")]
pub mod zlib {
    //! Compress and decompress with zlib.
    use crate::Result;
    use flate2::{
        write::{ZlibDecoder, ZlibEncoder},
        Compression,
    };
    use std::io::Write;

    /// Compress bytes.
    pub fn encode_all(buf: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(buf)?;
        Ok(encoder.finish()?)
    }

    /// Decompress bytes.
    pub fn decode_all(buf: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = ZlibDecoder::new(Vec::new());
        decoder.write_all(buf)?;
        Ok(decoder.finish()?)
    }

    #[cfg(test)]
    mod test {
        use super::*;
        #[test]
        fn zlib_encode_decode() -> anyhow::Result<()> {
            let bytes = "hello ooooooooooooooo world!".as_bytes();
            let deflated = encode_all(bytes)?;
            let inflated = decode_all(&deflated)?;
            assert_eq!(bytes, &inflated);
            Ok(())
        }
    }
}

// Can't use zstd right now due to compilation error on MacOS
// with wasm32-unknown-unknown.
// See: https://github.com/gyscos/zstd-rs/issues/302
//
// Later we should switch once this bug has been fixed!

#[cfg(feature = "compression-zstd")]
pub mod zstd {
    //! Compress and decompress with zstd.

    use crate::Result;
    use std::io::Read;

    /// Compress bytes.
    pub fn encode_all<R: Read>(read: R) -> Result<Vec<u8>> {
        Ok(zstd::encode_all(read, 20)?)
    }

    /// Decompress bytes.
    pub fn decode_all<R: Read>(read: R) -> Result<Vec<u8>> {
        Ok(zstd::decode_all(read)?)
    }

    #[cfg(test)]
    mod test {
        use super::*;
        #[test]
        fn zstd_encode_decode() -> anyhow::Result<()> {
            let bytes = "hello ooooooooooooooo world!".as_bytes();
            let deflated = encode_all(bytes)?;
            let inflated = decode_all(deflated.as_slice())?;
            assert_eq!(bytes, &inflated);
            Ok(())
        }
    }
}
