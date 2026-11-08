use std::io::Read;

/// Compression formats supported for OCI image layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionFormat {
    Gzip,
    Zstd,
    Uncompressed,
}

impl CompressionFormat {
    /// Detects the compression format by reading magic bytes.
    pub fn detect(header: &[u8]) -> Self {
        if header.len() >= 2 && header[0] == 0x1f && header[1] == 0x8b {
            Self::Gzip
        } else if header.len() >= 4 && header[0..4] == [0x28, 0xb5, 0x2f, 0xfd] {
            Self::Zstd
        } else {
            Self::Uncompressed
        }
    }

    /// Creates a streaming decompressor wrapping the input reader.
    pub fn decompress<'a, R: Read + 'a>(self, reader: R) -> Box<dyn Read + 'a> {
        match self {
            Self::Gzip => Box::new(flate2::read::GzDecoder::new(reader)),
            Self::Zstd => match zstd::stream::Decoder::new(reader) {
                Ok(d) => Box::new(d),
                Err(_) => Box::new(std::io::empty()),
            },
            Self::Uncompressed => Box::new(reader),
        }
    }
}
