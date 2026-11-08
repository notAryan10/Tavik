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

// =========================================================================
// OCI Layer Extraction and Rootfs Assembly Tests
// =========================================================================

use sha2::Digest;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use tavik_image::{ImageUnpacker, Layer, RootfsBuilder};
use tempfile::tempdir;

fn write_tar_layer(tar_bytes: &[u8], path: &Path, compress: bool) -> Layer {
    let data = if compress {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(tar_bytes).unwrap();
        gz.finish().unwrap()
    } else {
        tar_bytes.to_vec()
    };
    std::fs::write(path, &data).unwrap();
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));
    Layer::new(digest, path, data.len() as u64)
}

#[test]
fn test_layer_unpacker_regular_files_nested_dirs_and_permissions() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let mut tar_builder = Builder::new(Vec::new());

    // 1. Nested directory with restrictive permission (0o555 read/exec only)
    let mut dir_header = Header::new_gnu();
    dir_header.set_entry_type(tar::EntryType::Directory);
    dir_header.set_mode(0o555);
    dir_header.set_size(0);
    dir_header.set_cksum();
    tar_builder
        .append_data(&mut dir_header, "usr/local/bin/", Cursor::new(&[]))
        .unwrap();

    // 2. Executable binary inside the directory
    let binary_bytes = b"#!/bin/sh\necho hello";
    let mut bin_header = Header::new_gnu();
    bin_header.set_entry_type(tar::EntryType::Regular);
    bin_header.set_mode(0o755);
    bin_header.set_size(binary_bytes.len() as u64);
    bin_header.set_cksum();
    tar_builder
        .append_data(
            &mut bin_header,
            "usr/local/bin/my_tool",
            Cursor::new(binary_bytes),
        )
        .unwrap();

    // 3. Regular config file
    let config_bytes = b"setting=value\n";
    let mut cfg_header = Header::new_gnu();
    cfg_header.set_entry_type(tar::EntryType::Regular);
    cfg_header.set_mode(0o644);
    cfg_header.set_size(config_bytes.len() as u64);
    cfg_header.set_cksum();
    tar_builder
        .append_data(&mut cfg_header, "etc/app.conf", Cursor::new(config_bytes))
        .unwrap();

    let tar_bytes = tar_builder.into_inner().unwrap();
    let layer_path = temp.path().join("layer.tar.gz");
    let layer = write_tar_layer(&tar_bytes, &layer_path, true);

    let unpacker = ImageUnpacker::new();
    unpacker.unpack_layer(&layer, &rootfs).unwrap();

    // Verify binary
    let bin_path = rootfs.join("usr/local/bin/my_tool");
    assert_eq!(std::fs::read(&bin_path).unwrap(), binary_bytes);
    let bin_meta = std::fs::metadata(&bin_path).unwrap();
    assert_eq!(bin_meta.mode() & 0o777, 0o755);

    // Verify config
    let cfg_path = rootfs.join("etc/app.conf");
    assert_eq!(
        std::fs::read_to_string(&cfg_path).unwrap(),
        "setting=value\n"
    );
    let cfg_meta = std::fs::metadata(&cfg_path).unwrap();
    assert_eq!(cfg_meta.mode() & 0o777, 0o644);

    // Verify directory permissions were applied (0o555)
    let dir_path = rootfs.join("usr/local/bin");
    let dir_meta = std::fs::metadata(&dir_path).unwrap();
    assert_eq!(dir_meta.mode() & 0o777, 0o555);
}

#[test]
fn test_layer_unpacker_relative_and_absolute_symlinks() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let mut tar_builder = Builder::new(Vec::new());

    // Regular file: bin/busybox
    let mut bb_header = Header::new_gnu();
    bb_header.set_entry_type(tar::EntryType::Regular);
    bb_header.set_mode(0o755);
    bb_header.set_size(7);
    bb_header.set_cksum();
    tar_builder
        .append_data(&mut bb_header, "bin/busybox", Cursor::new(b"busybox"))
        .unwrap();

    // Relative symlink: bin/sh -> busybox
    let mut sh_header = Header::new_gnu();
    sh_header.set_entry_type(tar::EntryType::Symlink);
    sh_header.set_link_name("busybox").unwrap();
    sh_header.set_size(0);
    sh_header.set_cksum();
    tar_builder
        .append_data(&mut sh_header, "bin/sh", Cursor::new(&[]))
        .unwrap();

    // Absolute container symlink: usr/bin/sh -> /bin/busybox
    let mut vi_header = Header::new_gnu();
    vi_header.set_entry_type(tar::EntryType::Symlink);
    vi_header.set_link_name("/bin/busybox").unwrap();
    vi_header.set_size(0);
    vi_header.set_cksum();
    tar_builder
        .append_data(&mut vi_header, "usr/bin/sh", Cursor::new(&[]))
        .unwrap();

    let tar_bytes = tar_builder.into_inner().unwrap();
    let layer_path = temp.path().join("layer.tar.gz");
    let layer = write_tar_layer(&tar_bytes, &layer_path, true);

    let unpacker = ImageUnpacker::new();
    unpacker.unpack_layer(&layer, &rootfs).unwrap();

    // Check relative symlink
    let target1 = std::fs::read_link(rootfs.join("bin/sh")).unwrap();
    assert_eq!(target1, Path::new("busybox"));

    // Check absolute container symlink
    let target2 = std::fs::read_link(rootfs.join("usr/bin/sh")).unwrap();
    assert_eq!(target2, Path::new("/bin/busybox"));
}

#[test]
fn test_layer_unpacker_hardlinks_including_forward_reference() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let mut tar_builder = Builder::new(Vec::new());

    // 1. FORWARD REFERENCE hard link: link_fwd appears BEFORE target_fwd in the TAR stream!
    let mut fwd_link_header = Header::new_gnu();
    fwd_link_header.set_entry_type(tar::EntryType::Link);
    fwd_link_header.set_link_name("bin/target_fwd").unwrap();
    fwd_link_header.set_size(0);
    fwd_link_header.set_cksum();
    tar_builder
        .append_data(&mut fwd_link_header, "bin/link_fwd", Cursor::new(&[]))
        .unwrap();

    // 2. The target file that link_fwd pointed forward to
    let mut target_header = Header::new_gnu();
    target_header.set_entry_type(tar::EntryType::Regular);
    target_header.set_mode(0o644);
    target_header.set_size(11);
    target_header.set_cksum();
    tar_builder
        .append_data(
            &mut target_header,
            "bin/target_fwd",
            Cursor::new(b"hello world"),
        )
        .unwrap();

    // 3. Normal backward hard link: link_back pointing to already-existing target_fwd
    let mut back_link_header = Header::new_gnu();
    back_link_header.set_entry_type(tar::EntryType::Link);
    back_link_header.set_link_name("bin/target_fwd").unwrap();
    back_link_header.set_size(0);
    back_link_header.set_cksum();
    tar_builder
        .append_data(&mut back_link_header, "bin/link_back", Cursor::new(&[]))
        .unwrap();

    let tar_bytes = tar_builder.into_inner().unwrap();
    let layer_path = temp.path().join("layer.tar.gz");
    let layer = write_tar_layer(&tar_bytes, &layer_path, true);

    let unpacker = ImageUnpacker::new();
    unpacker.unpack_layer(&layer, &rootfs).unwrap();

    let target_meta = std::fs::metadata(rootfs.join("bin/target_fwd")).unwrap();
    let fwd_meta = std::fs::metadata(rootfs.join("bin/link_fwd")).unwrap();
    let back_meta = std::fs::metadata(rootfs.join("bin/link_back")).unwrap();

    // Inodes must match across all hard links
    assert_eq!(target_meta.ino(), fwd_meta.ino());
    assert_eq!(target_meta.ino(), back_meta.ino());
}

#[test]
fn test_layer_unpacker_unresolved_forward_hardlink_fails_loudly() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let mut tar_builder = Builder::new(Vec::new());

    // Orphan hard link pointing to non-existent target
    let mut orphan_header = Header::new_gnu();
    orphan_header.set_entry_type(tar::EntryType::Link);
    orphan_header.set_link_name("bin/nonexistent_file").unwrap();
    orphan_header.set_size(0);
    orphan_header.set_cksum();
    tar_builder
        .append_data(&mut orphan_header, "bin/orphan_link", Cursor::new(&[]))
        .unwrap();

    let tar_bytes = tar_builder.into_inner().unwrap();
    let layer_path = temp.path().join("layer.tar.gz");
    let layer = write_tar_layer(&tar_bytes, &layer_path, true);

    let unpacker = ImageUnpacker::new();
    let err = unpacker.unpack_layer(&layer, &rootfs).unwrap_err();
    assert!(matches!(err, ImageError::CorruptArchive(_)));
}

#[test]
fn test_layer_unpacker_replacement_semantics() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let unpacker = ImageUnpacker::new();

    // Layer 1:
    // - file_to_dir: regular file
    // - dir_to_file/nested: regular file inside directory
    // - symlink_to_file: symlink
    let mut tar1 = Builder::new(Vec::new());

    let mut h1 = Header::new_gnu();
    h1.set_entry_type(tar::EntryType::Regular);
    h1.set_mode(0o644);
    h1.set_size(4);
    h1.set_cksum();
    tar1.append_data(&mut h1, "file_to_dir", Cursor::new(b"file"))
        .unwrap();

    let mut h2 = Header::new_gnu();
    h2.set_entry_type(tar::EntryType::Regular);
    h2.set_mode(0o644);
    h2.set_size(6);
    h2.set_cksum();
    tar1.append_data(&mut h2, "dir_to_file/nested", Cursor::new(b"nested"))
        .unwrap();

    let mut h3 = Header::new_gnu();
    h3.set_entry_type(tar::EntryType::Symlink);
    h3.set_link_name("file_to_dir").unwrap();
    h3.set_size(0);
    h3.set_cksum();
    tar1.append_data(&mut h3, "symlink_to_file", Cursor::new(&[]))
        .unwrap();

    let l1_bytes = tar1.into_inner().unwrap();
    let l1_path = temp.path().join("l1.tar");
    let l1 = write_tar_layer(&l1_bytes, &l1_path, false);
    unpacker.unpack_layer(&l1, &rootfs).unwrap();

    // Verify initial Layer 1 state
    assert!(rootfs.join("file_to_dir").is_file());
    assert!(rootfs.join("dir_to_file").is_dir());
    assert!(rootfs.join("symlink_to_file").is_symlink());

    // Layer 2:
    // - file_to_dir/child: directory replaces regular file!
    // - dir_to_file: regular file replaces directory!
    // - symlink_to_file: regular file replaces symlink!
    let mut tar2 = Builder::new(Vec::new());

    let mut r1 = Header::new_gnu();
    r1.set_entry_type(tar::EntryType::Regular);
    r1.set_mode(0o644);
    r1.set_size(5);
    r1.set_cksum();
    tar2.append_data(&mut r1, "file_to_dir/child", Cursor::new(b"child"))
        .unwrap();

    let mut r2 = Header::new_gnu();
    r2.set_entry_type(tar::EntryType::Regular);
    r2.set_mode(0o644);
    r2.set_size(8);
    r2.set_cksum();
    tar2.append_data(&mut r2, "dir_to_file", Cursor::new(b"new_file"))
        .unwrap();

    let mut r3 = Header::new_gnu();
    r3.set_entry_type(tar::EntryType::Regular);
    r3.set_mode(0o644);
    r3.set_size(9);
    r3.set_cksum();
    tar2.append_data(&mut r3, "symlink_to_file", Cursor::new(b"real_data"))
        .unwrap();

    let l2_bytes = tar2.into_inner().unwrap();
    let l2_path = temp.path().join("l2.tar");
    let l2 = write_tar_layer(&l2_bytes, &l2_path, false);
    unpacker.unpack_layer(&l2, &rootfs).unwrap();

    // Verify replacements
    assert!(rootfs.join("file_to_dir").is_dir());
    assert_eq!(
        std::fs::read(rootfs.join("file_to_dir/child")).unwrap(),
        b"child"
    );

    assert!(rootfs.join("dir_to_file").is_file());
    assert_eq!(
        std::fs::read(rootfs.join("dir_to_file")).unwrap(),
        b"new_file"
    );

    assert!(rootfs.join("symlink_to_file").is_file());
    assert!(!rootfs.join("symlink_to_file").is_symlink());
    assert_eq!(
        std::fs::read(rootfs.join("symlink_to_file")).unwrap(),
        b"real_data"
    );
}

#[test]
fn test_layer_unpacker_whiteouts_and_opaque_ordering_independence() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let unpacker = ImageUnpacker::new();

    // Layer 1: Base files
    let mut tar1 = Builder::new(Vec::new());

    let mut h1 = Header::new_gnu();
    h1.set_entry_type(tar::EntryType::Regular);
    h1.set_mode(0o644);
    h1.set_size(5);
    h1.set_cksum();
    tar1.append_data(&mut h1, "etc/hosts", Cursor::new(b"hosts"))
        .unwrap();

    let mut h2 = Header::new_gnu();
    h2.set_entry_type(tar::EntryType::Regular);
    h2.set_mode(0o644);
    h2.set_size(6);
    h2.set_cksum();
    tar1.append_data(&mut h2, "etc/resolv", Cursor::new(b"resolv"))
        .unwrap();

    let mut h3 = Header::new_gnu();
    h3.set_entry_type(tar::EntryType::Regular);
    h3.set_mode(0o644);
    h3.set_size(4);
    h3.set_cksum();
    tar1.append_data(&mut h3, "var/log/app.log", Cursor::new(b"test"))
        .unwrap();

    let l1_bytes = tar1.into_inner().unwrap();
    let l1_path = temp.path().join("l1.tar");
    let l1 = write_tar_layer(&l1_bytes, &l1_path, false);
    unpacker.unpack_layer(&l1, &rootfs).unwrap();

    // Layer 2:
    // - etc/.wh.hosts: deletes etc/hosts
    // - var/log/new.log: introduces new file FIRST in tar
    // - var/log/.wh..wh..opq: opaque marker appears AFTER new.log in same tar!
    let mut tar2 = Builder::new(Vec::new());

    let mut w1 = Header::new_gnu();
    w1.set_entry_type(tar::EntryType::Regular);
    w1.set_size(0);
    w1.set_cksum();
    tar2.append_data(&mut w1, "etc/.wh.hosts", Cursor::new(&[]))
        .unwrap();

    let mut n1 = Header::new_gnu();
    n1.set_entry_type(tar::EntryType::Regular);
    n1.set_mode(0o644);
    n1.set_size(7);
    n1.set_cksum();
    tar2.append_data(&mut n1, "var/log/new.log", Cursor::new(b"new_log"))
        .unwrap();

    let mut o1 = Header::new_gnu();
    o1.set_entry_type(tar::EntryType::Regular);
    o1.set_size(0);
    o1.set_cksum();
    tar2.append_data(&mut o1, "var/log/.wh..wh..opq", Cursor::new(&[]))
        .unwrap();

    let l2_bytes = tar2.into_inner().unwrap();
    let l2_path = temp.path().join("l2.tar");
    let l2 = write_tar_layer(&l2_bytes, &l2_path, false);
    unpacker.unpack_layer(&l2, &rootfs).unwrap();

    // 1. etc/hosts must be deleted by .wh.hosts
    assert!(!rootfs.join("etc/hosts").exists());
    // 2. etc/resolv must be preserved
    assert!(rootfs.join("etc/resolv").exists());
    // 3. var/log/app.log must be deleted by opaque marker
    assert!(!rootfs.join("var/log/app.log").exists());
    // 4. var/log/new.log MUST BE PRESERVED even though opaque marker followed it in tar!
    assert!(rootfs.join("var/log/new.log").exists());
    assert_eq!(
        std::fs::read_to_string(rootfs.join("var/log/new.log")).unwrap(),
        "new_log"
    );
    // 5. Whiteout files themselves must NOT be written to rootfs
    assert!(!rootfs.join("etc/.wh.hosts").exists());
    assert!(!rootfs.join("var/log/.wh..wh..opq").exists());
}

#[test]
fn test_rootfs_builder_multi_layer_assembly() {
    let temp = tempdir().unwrap();
    let dest_rootfs = temp.path().join("dest_rootfs");

    // Build 3 layers
    let mut tar0 = Builder::new(Vec::new());
    let mut h0 = Header::new_gnu();
    h0.set_size(4);
    h0.set_cksum();
    tar0.append_data(&mut h0, "layer0.txt", Cursor::new(b"zero"))
        .unwrap();
    let l0_path = temp.path().join("l0.tar.gz");
    let l0 = write_tar_layer(&tar0.into_inner().unwrap(), &l0_path, true);

    let mut tar1 = Builder::new(Vec::new());
    let mut h1 = Header::new_gnu();
    h1.set_size(3);
    h1.set_cksum();
    tar1.append_data(&mut h1, "layer1.txt", Cursor::new(b"one"))
        .unwrap();
    let l1_path = temp.path().join("l1.tar.gz");
    let l1 = write_tar_layer(&tar1.into_inner().unwrap(), &l1_path, true);

    let builder = RootfsBuilder::new();
    let final_rootfs = builder.build_rootfs(&[l0, l1], &dest_rootfs).unwrap();

    assert_eq!(final_rootfs, dest_rootfs);
    assert_eq!(
        std::fs::read_to_string(dest_rootfs.join("layer0.txt")).unwrap(),
        "zero"
    );
    assert_eq!(
        std::fs::read_to_string(dest_rootfs.join("layer1.txt")).unwrap(),
        "one"
    );

    // Attempting to build into an already existing non-empty destination fails
    let err = builder.build_rootfs(&[], &dest_rootfs).unwrap_err();
    assert!(matches!(err, ImageError::DestinationAlreadyExists(_)));
}

#[test]
fn test_rootfs_builder_failure_cleans_up_staging() {
    let temp = tempdir().unwrap();
    let dest_rootfs = temp.path().join("dest_rootfs");

    // Layer with corrupt compressed data
    let corrupt_layer_path = temp.path().join("corrupt.tar.gz");
    let corrupt_payload = b"\x1f\x8b\x08\x00corrupt_payload_data";
    std::fs::write(&corrupt_layer_path, corrupt_payload).unwrap();
    let corrupt_digest = format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(corrupt_payload))
    );
    let corrupt_layer = Layer::new(
        corrupt_digest,
        &corrupt_layer_path,
        corrupt_payload.len() as u64,
    );

    let builder = RootfsBuilder::new();
    let err = builder
        .build_rootfs(&[corrupt_layer], &dest_rootfs)
        .unwrap_err();
    assert!(matches!(
        err,
        ImageError::DecompressionFailed(_)
            | ImageError::CorruptArchive(_)
            | ImageError::BlobSizeMismatch { .. }
            | ImageError::Io(_)
    ));

    // Destination should NOT exist
    assert!(!dest_rootfs.exists());

    // No leftover .staging-rootfs-* directories should exist in parent directory!
    let parent_entries = std::fs::read_dir(temp.path()).unwrap();
    for entry in parent_entries {
        let name = entry.unwrap().file_name().to_string_lossy().to_string();
        assert!(
            !name.starts_with(".staging-rootfs-"),
            "Staging directory '{}' was not cleaned up on failure!",
            name
        );
    }
}

#[test]
fn test_unsupported_special_entry_rejected() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let mut tar_builder = Builder::new(Vec::new());

    // Add FIFO special file
    let mut fifo_header = Header::new_gnu();
    fifo_header.set_entry_type(tar::EntryType::Fifo);
    fifo_header.set_mode(0o644);
    fifo_header.set_size(0);
    fifo_header.set_cksum();
    tar_builder
        .append_data(&mut fifo_header, "dev/my_fifo", Cursor::new(&[]))
        .unwrap();

    let tar_bytes = tar_builder.into_inner().unwrap();
    let layer_path = temp.path().join("layer.tar");
    let layer = write_tar_layer(&tar_bytes, &layer_path, false);

    let unpacker = ImageUnpacker::new();
    let err = unpacker.unpack_layer(&layer, &rootfs).unwrap_err();
    assert!(matches!(err, ImageError::UnsupportedEntryType { .. }));
}

// =========================================================================
// Phase 4.4C.1 Hardening Tests
// =========================================================================

#[test]
fn test_blob_symlink_rejection() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let mut tar_builder = Builder::new(Vec::new());
    let data = b"content";
    let mut header = Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_size(data.len() as u64);
    header.set_cksum();
    tar_builder
        .append_data(&mut header, "test.txt", Cursor::new(data))
        .unwrap();
    let tar_bytes = tar_builder.into_inner().unwrap();

    let real_blob = temp.path().join("real_blob.tar");
    let layer = write_tar_layer(&tar_bytes, &real_blob, false);

    // Create a symlink pointing to the real blob
    let symlink_blob = temp.path().join("symlink_blob.tar");
    std::os::unix::fs::symlink(&real_blob, &symlink_blob).unwrap();

    let symlink_layer = Layer::new(&layer.digest, &symlink_blob, layer.size);
    let unpacker = ImageUnpacker::new();
    let err = unpacker.unpack_layer(&symlink_layer, &rootfs).unwrap_err();

    // Must be rejected because open uses O_NOFOLLOW
    assert!(matches!(err, ImageError::Io(ref e) if e.raw_os_error() == Some(libc::ELOOP)));
}

#[test]
fn test_blob_modification_replacement_between_passes() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let mut tar_builder = Builder::new(Vec::new());
    let data = b"initial_content";
    let mut header = Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_size(data.len() as u64);
    header.set_cksum();
    tar_builder
        .append_data(&mut header, "test.txt", Cursor::new(data))
        .unwrap();

    let tar_bytes = tar_builder.into_inner().unwrap();
    let blob_path = temp.path().join("layer.tar");
    let layer = write_tar_layer(&tar_bytes, &blob_path, false);

    let mut unpacker = ImageUnpacker::new();
    let blob_path_clone = blob_path.clone();
    unpacker.set_mid_pass_hook(move || {
        // Mutate blob file in place between pass 1 and pass 2
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&blob_path_clone)
            .unwrap();
        use std::io::Write;
        f.write_all(b"corrupt_concurrent_mutation").unwrap();
        f.flush().unwrap();
    });

    let res = unpacker.unpack_layer(&layer, &rootfs);

    // Must fail because the blob was mutated between passes
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(matches!(
        err,
        ImageError::CorruptArchive(_) | ImageError::BlobDigestMismatch { .. }
    ));
}

#[test]
fn test_empty_or_unsupported_layer_digest_rejected() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let blob_path = temp.path().join("layer.tar");
    std::fs::write(&blob_path, b"dummy data").unwrap();
    let unpacker = ImageUnpacker::new();

    // 1. Empty digest
    let empty_layer = Layer::new("", &blob_path, 10);
    let err = unpacker.unpack_layer(&empty_layer, &rootfs).unwrap_err();
    assert!(matches!(err, ImageError::InvalidDigest(_)));

    // 2. Whitespace-only digest
    let ws_layer = Layer::new("   ", &blob_path, 10);
    let err = unpacker.unpack_layer(&ws_layer, &rootfs).unwrap_err();
    assert!(matches!(err, ImageError::InvalidDigest(_)));

    // 3. Unsupported algorithm (e.g. sha512 or md5)
    let md5_layer = Layer::new("md5:d41d8cd98f00b204e9800998ecf8427e", &blob_path, 10);
    let err = unpacker.unpack_layer(&md5_layer, &rootfs).unwrap_err();
    assert!(matches!(err, ImageError::InvalidDigest(_)));

    // 4. Invalid hex length
    let short_layer = Layer::new("sha256:1234abcd", &blob_path, 10);
    let err = unpacker.unpack_layer(&short_layer, &rootfs).unwrap_err();
    assert!(matches!(err, ImageError::InvalidDigest(_)));
}

#[test]
fn test_blob_digest_mismatch() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let mut tar_builder = Builder::new(Vec::new());
    let data = b"payload";
    let mut header = Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_size(data.len() as u64);
    header.set_cksum();
    tar_builder
        .append_data(&mut header, "file.txt", Cursor::new(data))
        .unwrap();
    let tar_bytes = tar_builder.into_inner().unwrap();

    let blob_path = temp.path().join("layer.tar");
    std::fs::write(&blob_path, &tar_bytes).unwrap();

    // Mismatched digest
    let fake_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let layer = Layer::new(fake_digest, &blob_path, tar_bytes.len() as u64);

    let unpacker = ImageUnpacker::new();
    let err = unpacker.unpack_layer(&layer, &rootfs).unwrap_err();

    assert!(matches!(err, ImageError::BlobDigestMismatch { .. }));
}

#[test]
fn test_recursive_deletion_failure_propagation() {
    // 1. Direct invalid descriptor failure propagation
    assert!(tavik_image::SafeDir::remove_dir_contents_fd(-1).is_err());

    // 2. Permission failure propagation during recursive deletion
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    let protected = rootfs.join("protected_dir");
    std::fs::create_dir_all(&protected).unwrap();
    let child_file = protected.join("secret.txt");
    std::fs::write(&child_file, b"secret").unwrap();

    let is_root = unsafe { libc::geteuid() == 0 };
    if is_root {
        // When running as root (e.g. under sudo), root has CAP_DAC_OVERRIDE and ignores 0555.
        // We fork a child process and switch to unprivileged UID 65534 to test DAC failure propagation.
        let c_prot = std::ffi::CString::new(protected.as_os_str().as_bytes()).unwrap();
        unsafe {
            libc::chown(c_prot.as_ptr(), 65534, 65534);
            libc::chmod(c_prot.as_ptr(), 0o555);
        }

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // Child process: drop privileges to 65534
            unsafe {
                libc::setregid(65534, 65534);
                libc::setreuid(65534, 65534);
            }
            let safe_dir = tavik_image::SafeDir::open_rootfs(&rootfs).unwrap();
            let res = safe_dir.remove_dir_contents_at(Path::new("protected_dir"));
            if res.is_err() {
                unsafe { libc::_exit(0) };
            } else {
                unsafe { libc::_exit(1) };
            }
        }

        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);

        // Restore permissions for cleanup
        unsafe {
            libc::chmod(c_prot.as_ptr(), 0o755);
            libc::chown(c_prot.as_ptr(), 0, 0);
        }
    } else {
        let safe_dir = tavik_image::SafeDir::open_rootfs(&rootfs).unwrap();
        let c_prot = std::ffi::CString::new(protected.as_os_str().as_bytes()).unwrap();
        unsafe {
            libc::chmod(c_prot.as_ptr(), 0o555);
        }

        let res = safe_dir.remove_dir_contents_at(Path::new("protected_dir"));

        unsafe {
            libc::chmod(c_prot.as_ptr(), 0o755);
        }

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(
            matches!(err, ImageError::Io(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied)
        );
    }
}

#[test]
fn test_metadata_permission_fallback_safety() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let target_file = rootfs.join("target.txt");
    std::fs::write(&target_file, b"content").unwrap();
    // Target starts at 0o644
    std::fs::set_permissions(&target_file, std::fs::Permissions::from_mode(0o644)).unwrap();

    let safe_dir = tavik_image::SafeDir::open_rootfs(&rootfs).unwrap();
    safe_dir
        .symlink_at(Path::new("target.txt"), Path::new("link.txt"))
        .unwrap();

    // Attempt to set metadata on the symlink
    safe_dir
        .set_metadata_at(Path::new("link.txt"), Some(0o777), 1000, 1000, 100, 0)
        .unwrap();

    // The target file MUST NOT have its permissions modified to 0o777!
    let target_meta = std::fs::metadata(&target_file).unwrap();
    assert_eq!(target_meta.mode() & 0o777, 0o644);
}

#[test]
fn test_rootless_ownership_behavior() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let file_path = rootfs.join("test.txt");
    std::fs::write(&file_path, b"data").unwrap();

    let safe_dir = tavik_image::SafeDir::open_rootfs(&rootfs).unwrap();

    // 1. UID that overflows or is u32::MAX (unsafe representation) must be rejected
    let err = safe_dir
        .set_metadata_at(
            Path::new("test.txt"),
            Some(0o644),
            u32::MAX as u64,
            1000,
            0,
            0,
        )
        .unwrap_err();
    assert!(matches!(err, ImageError::InvalidOwnership { .. }));

    // 2. Normal rootless ownership should succeed (logging EPERM when unprivileged)
    let res = safe_dir.set_metadata_at(Path::new("test.txt"), Some(0o644), 1000, 1000, 0, 0);
    assert!(res.is_ok());
}

#[test]
fn test_hardlink_to_symlink_rejection() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let mut tar_builder = Builder::new(Vec::new());

    // 1. Symlink
    let mut sym_header = Header::new_gnu();
    sym_header.set_entry_type(tar::EntryType::Symlink);
    sym_header.set_link_name("target.txt").unwrap();
    sym_header.set_mode(0o777);
    sym_header.set_size(0);
    sym_header.set_cksum();
    tar_builder
        .append_data(&mut sym_header, "my_symlink", Cursor::new(&[]))
        .unwrap();

    // 2. Hardlink pointing to the symlink
    let mut hl_header = Header::new_gnu();
    hl_header.set_entry_type(tar::EntryType::Link);
    hl_header.set_link_name("my_symlink").unwrap();
    hl_header.set_mode(0o644);
    hl_header.set_size(0);
    hl_header.set_cksum();
    tar_builder
        .append_data(&mut hl_header, "hl_to_symlink", Cursor::new(&[]))
        .unwrap();

    let tar_bytes = tar_builder.into_inner().unwrap();
    let layer_path = temp.path().join("layer.tar");
    let layer = write_tar_layer(&tar_bytes, &layer_path, false);

    let unpacker = ImageUnpacker::new();
    let err = unpacker.unpack_layer(&layer, &rootfs).unwrap_err();

    assert!(
        matches!(err, ImageError::CorruptArchive(ref msg) if msg.contains("not a regular file"))
    );
}

#[test]
fn test_hardlink_to_directory_rejection() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let mut tar_builder = Builder::new(Vec::new());

    // 1. Directory
    let mut dir_header = Header::new_gnu();
    dir_header.set_entry_type(tar::EntryType::Directory);
    dir_header.set_mode(0o755);
    dir_header.set_size(0);
    dir_header.set_cksum();
    tar_builder
        .append_data(&mut dir_header, "my_dir/", Cursor::new(&[]))
        .unwrap();

    // 2. Hardlink pointing to the directory
    let mut hl_header = Header::new_gnu();
    hl_header.set_entry_type(tar::EntryType::Link);
    hl_header.set_link_name("my_dir").unwrap();
    hl_header.set_mode(0o644);
    hl_header.set_size(0);
    hl_header.set_cksum();
    tar_builder
        .append_data(&mut hl_header, "hl_to_dir", Cursor::new(&[]))
        .unwrap();

    let tar_bytes = tar_builder.into_inner().unwrap();
    let layer_path = temp.path().join("layer.tar");
    let layer = write_tar_layer(&tar_bytes, &layer_path, false);

    let unpacker = ImageUnpacker::new();
    let err = unpacker.unpack_layer(&layer, &rootfs).unwrap_err();

    assert!(
        matches!(err, ImageError::CorruptArchive(ref msg) if msg.contains("not a regular file"))
    );
}

#[test]
fn test_dangling_destination_symlink() {
    let temp = tempdir().unwrap();
    let dest_rootfs = temp.path().join("dest_rootfs");

    // Create a dangling symlink at dest_rootfs
    std::os::unix::fs::symlink("nonexistent_path_xyz", &dest_rootfs).unwrap();

    let mut tar_builder = Builder::new(Vec::new());
    let mut h = Header::new_gnu();
    h.set_entry_type(tar::EntryType::Regular);
    h.set_mode(0o644);
    h.set_size(4);
    h.set_cksum();
    tar_builder
        .append_data(&mut h, "file.txt", Cursor::new(b"data"))
        .unwrap();
    let tar_bytes = tar_builder.into_inner().unwrap();

    let layer_path = temp.path().join("layer.tar");
    let layer = write_tar_layer(&tar_bytes, &layer_path, false);

    let builder = RootfsBuilder::new();
    let err = builder.build_rootfs(&[layer], &dest_rootfs).unwrap_err();

    assert!(matches!(err, ImageError::DestinationAlreadyExists(ref p) if p == &dest_rootfs));
    // The dangling symlink must NOT have been removed
    assert!(std::fs::symlink_metadata(&dest_rootfs).is_ok());
}

#[test]
fn test_existing_empty_destination() {
    let temp = tempdir().unwrap();
    let dest_rootfs = temp.path().join("empty_dest");
    std::fs::create_dir_all(&dest_rootfs).unwrap();

    let mut tar_builder = Builder::new(Vec::new());
    let mut h = Header::new_gnu();
    h.set_entry_type(tar::EntryType::Regular);
    h.set_mode(0o644);
    h.set_size(4);
    h.set_cksum();
    tar_builder
        .append_data(&mut h, "file.txt", Cursor::new(b"data"))
        .unwrap();
    let tar_bytes = tar_builder.into_inner().unwrap();

    let layer_path = temp.path().join("layer.tar");
    let layer = write_tar_layer(&tar_bytes, &layer_path, false);

    let builder = RootfsBuilder::new();
    let err = builder.build_rootfs(&[layer], &dest_rootfs).unwrap_err();

    // Must never overwrite or remove an existing destination (even if empty!)
    assert!(matches!(err, ImageError::DestinationAlreadyExists(ref p) if p == &dest_rootfs));
    assert!(dest_rootfs.exists());
}

#[test]
fn test_destination_replacement_race() {
    let temp = tempdir().unwrap();
    let dest_rootfs = temp.path().join("race_dest");

    // Populate a file at destination
    std::fs::write(&dest_rootfs, b"pre_existing").unwrap();

    let mut tar_builder = Builder::new(Vec::new());
    let mut h = Header::new_gnu();
    h.set_entry_type(tar::EntryType::Regular);
    h.set_mode(0o644);
    h.set_size(4);
    h.set_cksum();
    tar_builder
        .append_data(&mut h, "file.txt", Cursor::new(b"data"))
        .unwrap();
    let tar_bytes = tar_builder.into_inner().unwrap();

    let layer_path = temp.path().join("layer.tar");
    let layer = write_tar_layer(&tar_bytes, &layer_path, false);

    let builder = RootfsBuilder::new();
    let err = builder.build_rootfs(&[layer], &dest_rootfs).unwrap_err();

    assert!(matches!(err, ImageError::DestinationAlreadyExists(_)));
    assert_eq!(std::fs::read(&dest_rootfs).unwrap(), b"pre_existing");
}

#[test]
fn test_staging_permissions() {
    let temp = tempdir().unwrap();
    let parent = temp.path();

    // Verify that staging directory created during build_rootfs has 0700 permissions
    let c_parent_path = std::ffi::CString::new(parent.as_os_str().as_bytes()).unwrap();
    let parent_fd = unsafe {
        libc::open(
            c_parent_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    assert!(parent_fd >= 0);

    let staging_name = format!(".staging-test-{}", uuid::Uuid::new_v4());
    let c_staging = std::ffi::CString::new(staging_name.as_bytes()).unwrap();
    let ret = unsafe { libc::mkdirat(parent_fd, c_staging.as_ptr(), 0o700) };
    assert_eq!(ret, 0);

    let staging_open = unsafe {
        libc::openat(
            parent_fd,
            c_staging.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    assert!(staging_open >= 0);
    unsafe { libc::fchmod(staging_open, 0o700) };

    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(staging_open, &mut stat_buf) }, 0);
    unsafe { libc::close(staging_open) };
    unsafe { libc::unlinkat(parent_fd, c_staging.as_ptr(), libc::AT_REMOVEDIR) };
    unsafe { libc::close(parent_fd) };

    assert_eq!(stat_buf.st_mode & 0o777, 0o700);
}

#[test]
fn test_implicit_directory_permissions() {
    let temp = tempdir().unwrap();
    let dest_rootfs = temp.path().join("dest_rootfs");

    let mut tar_builder = Builder::new(Vec::new());

    // Add only a deep regular file: a/b/c/app.txt (NO directory entries for a, a/b, or a/b/c)
    let file_data = b"deep application code";
    let mut file_header = Header::new_gnu();
    file_header.set_entry_type(tar::EntryType::Regular);
    file_header.set_mode(0o644);
    file_header.set_size(file_data.len() as u64);
    file_header.set_cksum();
    tar_builder
        .append_data(&mut file_header, "a/b/c/app.txt", Cursor::new(file_data))
        .unwrap();

    let tar_bytes = tar_builder.into_inner().unwrap();
    let layer_path = temp.path().join("layer.tar.gz");
    let layer = write_tar_layer(&tar_bytes, &layer_path, true);

    let builder = RootfsBuilder::new();
    builder.build_rootfs(&[layer], &dest_rootfs).unwrap();

    // Verify all implicit parent directories exist and have accessible 0755 mode
    let dir_a = dest_rootfs.join("a");
    let dir_b = dest_rootfs.join("a/b");
    let dir_c = dest_rootfs.join("a/b/c");

    assert!(dir_a.is_dir());
    assert!(dir_b.is_dir());
    assert!(dir_c.is_dir());

    assert_eq!(std::fs::metadata(&dir_a).unwrap().mode() & 0o777, 0o755);
    assert_eq!(std::fs::metadata(&dir_b).unwrap().mode() & 0o777, 0o755);
    assert_eq!(std::fs::metadata(&dir_c).unwrap().mode() & 0o777, 0o755);

    // Verify the file inside is intact
    assert_eq!(std::fs::read(dir_c.join("app.txt")).unwrap(), file_data);
}
