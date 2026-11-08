use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Cursor, Read, Write};
use tar::{Builder, Header};
use tavik_image::{ArchiveReader, CompressionFormat, ImageError};

fn create_test_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar_builder = Builder::new(Vec::new());
    for (name, content) in entries {
        let mut header = Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, *name, *content)
            .unwrap();
    }
    tar_builder.into_inner().unwrap()
}

#[test]
fn test_uncompressed_tar_detection_and_reading() {
    let raw_tar = create_test_tar(&[("hello.txt", b"Hello, uncompressed tar!")]);
    let cursor = Cursor::new(raw_tar.clone());

    let (format, mut reader) = ArchiveReader::open(cursor, None).unwrap();
    assert_eq!(format, CompressionFormat::Uncompressed);

    let mut decompressed = Vec::new();
    reader.read_to_end(&mut decompressed).unwrap();
    assert_eq!(decompressed, raw_tar);

    // Verify tar archive entries are intact (magic bytes were preserved)
    let mut archive = tar::Archive::new(Cursor::new(decompressed));
    let mut entries = archive.entries().unwrap();
    let mut entry = entries.next().unwrap().unwrap();
    let mut text = String::new();
    entry.read_to_string(&mut text).unwrap();
    assert_eq!(text, "Hello, uncompressed tar!");
}

#[test]
fn test_gzip_detection_and_decompression() {
    let raw_tar = create_test_tar(&[("greeting.txt", b"Hello from gzip compressed layer!")]);

    let mut gz_encoder = GzEncoder::new(Vec::new(), Compression::default());
    gz_encoder.write_all(&raw_tar).unwrap();
    let gz_bytes = gz_encoder.finish().unwrap();

    let (format, mut reader) = ArchiveReader::open(Cursor::new(gz_bytes), None).unwrap();
    assert_eq!(format, CompressionFormat::Gzip);

    let mut decompressed = Vec::new();
    reader.read_to_end(&mut decompressed).unwrap();
    assert_eq!(decompressed, raw_tar);

    let mut archive = tar::Archive::new(Cursor::new(decompressed));
    let mut entries = archive.entries().unwrap();
    let entry = entries.next().unwrap().unwrap();
    assert_eq!(entry.path().unwrap().to_str().unwrap(), "greeting.txt");
}

#[test]
fn test_zstd_detection_and_decompression() {
    let raw_tar = create_test_tar(&[("zstd.txt", b"Hello from zstd compressed layer!")]);

    let zstd_bytes = zstd::stream::encode_all(Cursor::new(&raw_tar), 3).unwrap();

    let (format, mut reader) = ArchiveReader::open(Cursor::new(zstd_bytes), None).unwrap();
    assert_eq!(format, CompressionFormat::Zstd);

    let mut decompressed = Vec::new();
    reader.read_to_end(&mut decompressed).unwrap();
    assert_eq!(decompressed, raw_tar);

    let mut archive = tar::Archive::new(Cursor::new(decompressed));
    let mut entries = archive.entries().unwrap();
    let entry = entries.next().unwrap().unwrap();
    assert_eq!(entry.path().unwrap().to_str().unwrap(), "zstd.txt");
}

#[test]
fn test_decompression_limit_exact_success() {
    let payload = b"exactly twenty bytes";
    assert_eq!(payload.len(), 20);

    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(payload).unwrap();
    let gz_bytes = gz.finish().unwrap();

    // Limit set to exactly payload length
    let (_format, mut reader) =
        ArchiveReader::open(Cursor::new(gz_bytes), Some(payload.len() as u64)).unwrap();

    let mut out = Vec::new();
    reader.read_to_end(&mut out).unwrap();
    assert_eq!(out, payload);
}

#[test]
fn test_decompression_limit_over_limit_failure() {
    let payload = b"this payload exceeds the allowed limit";
    let limit = 10u64;

    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(payload).unwrap();
    let gz_bytes = gz.finish().unwrap();

    let (_format, mut reader) = ArchiveReader::open(Cursor::new(gz_bytes), Some(limit)).unwrap();

    let mut out = Vec::new();
    let err = reader.read_to_end(&mut out).unwrap_err();

    // Verify the error is typed or represents limit exceeded
    let is_limit_err = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<ImageError>())
        .is_some_and(
            |e| matches!(e, ImageError::DecompressionLimitExceeded { limit: l } if *l == limit),
        );

    assert!(
        is_limit_err || err.to_string().contains("limit exceeded"),
        "Expected decompression limit error, got: {:?}",
        err
    );
}

#[test]
fn test_invalid_gzip_input_fails_loudly() {
    // Header indicates gzip (0x1f, 0x8b), but stream is corrupted
    let corrupt_gzip = vec![0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef];

    let (format, mut reader) = ArchiveReader::open(Cursor::new(corrupt_gzip), None).unwrap();
    assert_eq!(format, CompressionFormat::Gzip);

    let mut buf = Vec::new();
    let err = reader.read_to_end(&mut buf).unwrap_err();
    // Must NOT be empty ok result
    assert!(
        !err.to_string().is_empty(),
        "Corrupted gzip must return read error"
    );
}

#[test]
fn test_invalid_zstd_input_fails_loudly() {
    // Header indicates zstd (0x28, 0xb5, 0x2f, 0xfd), but content is corrupt
    let corrupt_zstd = vec![0x28, 0xb5, 0x2f, 0xfd, 0xff, 0xff, 0xff, 0xff];

    let (format, mut reader) = ArchiveReader::open(Cursor::new(corrupt_zstd), None).unwrap();
    assert_eq!(format, CompressionFormat::Zstd);

    let mut buf = Vec::new();
    let err = reader.read_to_end(&mut buf).unwrap_err();
    assert!(
        !err.to_string().is_empty(),
        "Corrupted zstd must return read error"
    );
}

#[test]
fn test_limited_reader_never_requests_more_than_remaining_limit() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingReader<R> {
        inner: R,
        max_requested: Arc<AtomicUsize>,
        total_delivered: Arc<AtomicUsize>,
    }

    impl<R: Read> Read for CountingReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let req_len = buf.len();
            let prev_max = self.max_requested.load(Ordering::SeqCst);
            if req_len > prev_max {
                self.max_requested.store(req_len, Ordering::SeqCst);
            }
            let n = self.inner.read(buf)?;
            self.total_delivered.fetch_add(n, Ordering::SeqCst);
            Ok(n)
        }
    }

    let max_req = Arc::new(AtomicUsize::new(0));
    let total_del = Arc::new(AtomicUsize::new(0));

    // 1 MiB payload
    let large_payload = vec![0x42u8; 1024 * 1024];
    let counting = CountingReader {
        inner: Cursor::new(large_payload),
        max_requested: Arc::clone(&max_req),
        total_delivered: Arc::clone(&total_del),
    };

    // Configure LimitedReader with a 64-byte limit
    let limit = 64u64;
    let mut limited = tavik_image::LimitedReader::new(counting, limit);

    // Caller provides a large 64 KiB buffer
    let mut big_buf = [0u8; 64 * 1024];

    // Read #1: should read exactly 64 bytes
    let n1 = limited.read(&mut big_buf).unwrap();
    assert_eq!(n1, 64);
    assert_eq!(limited.bytes_read(), 64);

    // Verify LimitedReader clamped request to remaining limit (64 bytes), NOT 64 KiB
    assert!(max_req.load(Ordering::SeqCst) <= 64);

    // Read #2: at exact limit, probe for EOF with a 1-byte buffer
    let err = limited.read(&mut big_buf).unwrap_err();
    assert!(err.to_string().contains("limit exceeded"));

    // Verify probe buffer was exactly 1 byte, so total delivered from inner is 64 + 1 = 65 bytes
    // It NEVER decompressed or read the rest of the 1 MiB payload!
    assert_eq!(total_del.load(Ordering::SeqCst), 65);
}

#[test]
fn test_limited_reader_exact_limit_probe_success() {
    let payload = vec![0xABu8; 128];
    let limit = 128u64;

    let mut limited = tavik_image::LimitedReader::new(Cursor::new(payload.clone()), limit);
    let mut out = Vec::new();
    // read_to_end consumes up to limit and probes for EOF
    limited.read_to_end(&mut out).unwrap();
    assert_eq!(out, payload);
    assert_eq!(limited.bytes_read(), limit);

    // Subsequent read returns EOF cleanly
    let mut extra = [0u8; 10];
    assert_eq!(limited.read(&mut extra).unwrap(), 0);
}

#[test]
fn test_limited_reader_one_byte_over_limit_triggers_probe_failure() {
    let payload = vec![0xABu8; 129]; // exactly 1 byte over limit
    let limit = 128u64;

    let mut limited = tavik_image::LimitedReader::new(Cursor::new(payload), limit);
    let mut out = Vec::new();
    let err = limited.read_to_end(&mut out).unwrap_err();
    assert!(err.to_string().contains("limit exceeded"));
}
