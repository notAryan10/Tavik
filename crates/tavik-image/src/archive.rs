use crate::error::ImageError;
use std::io::{self, Cursor, Read};

/// Compression formats supported for OCI image layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionFormat {
    Gzip,
    Zstd,
    Uncompressed,
}

impl CompressionFormat {
    /// Detects compression format from the initial magic bytes of a stream.
    pub fn detect(header: &[u8]) -> Self {
        if header.len() >= 2 && header[0] == 0x1f && header[1] == 0x8b {
            Self::Gzip
        } else if header.len() >= 4 && header[0..4] == [0x28, 0xb5, 0x2f, 0xfd] {
            Self::Zstd
        } else {
            Self::Uncompressed
        }
    }
}

/// A reader wrapper that enforces a strict maximum byte limit during decompression.
/// Returns an error if the decompressed stream exceeds the specified limit.
pub struct LimitedReader<R> {
    inner: R,
    limit: u64,
    bytes_read: u64,
}

impl<R: Read> LimitedReader<R> {
    pub fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            limit,
            bytes_read: 0,
        }
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read = self.bytes_read.saturating_add(n as u64);
        if self.bytes_read > self.limit {
            return Err(io::Error::other(ImageError::DecompressionLimitExceeded {
                limit: self.limit,
            }));
        }
        Ok(n)
    }
}

/// Helper that detects archive compression, constructs fallible decoders, and enforces decompression limits.
pub struct ArchiveReader;

impl ArchiveReader {
    /// Opens a stream, detecting whether it is Gzip, Zstd, or uncompressed TAR.
    /// Preserves all bytes consumed during magic detection by chaining them before the remainder of the reader.
    /// Decompression failures propagate as typed errors.
    pub fn open<R: Read + Send + 'static>(
        mut reader: R,
        decompression_limit: Option<u64>,
    ) -> Result<(CompressionFormat, Box<dyn Read + Send>), ImageError> {
        let mut magic = [0u8; 4];
        let mut n = 0;
        while n < 4 {
            match reader.read(&mut magic[n..]) {
                Ok(0) => break,
                Ok(read_bytes) => n += read_bytes,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(ImageError::Io(e)),
            }
        }

        let format = CompressionFormat::detect(&magic[..n]);
        let chained = Cursor::new(magic[..n].to_vec()).chain(reader);

        let decompressed: Box<dyn Read + Send> = match format {
            CompressionFormat::Gzip => Box::new(flate2::read::GzDecoder::new(chained)),
            CompressionFormat::Zstd => {
                let decoder = zstd::stream::read::Decoder::new(chained)
                    .map_err(|e| ImageError::DecompressionFailed(e.to_string()))?;
                Box::new(decoder)
            }
            CompressionFormat::Uncompressed => Box::new(chained),
        };

        let limited: Box<dyn Read + Send> = match decompression_limit {
            Some(limit) => Box::new(LimitedReader::new(decompressed, limit)),
            None => decompressed,
        };

        Ok((format, limited))
    }
}
