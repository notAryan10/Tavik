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
