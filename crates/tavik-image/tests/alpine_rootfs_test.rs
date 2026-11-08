use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use tar::{Builder, EntryType, Header};
use tavik_image::{
    normalize_symlink_target, sanitize_entry_path, ArchiveReader, CompressionFormat, ImageError,
    SafeDir, Whiteout,
};
use tempfile::tempdir;

fn build_alpine_layer_fixture() -> Vec<u8> {
    let mut tar_builder = Builder::new(Vec::new());

    // 1. Directory: /bin
    let mut dir_header = Header::new_gnu();
    dir_header.set_entry_type(EntryType::Directory);
    dir_header.set_mode(0o755);
    dir_header.set_size(0);
    dir_header.set_cksum();
    tar_builder
        .append_data(&mut dir_header, "bin/", Cursor::new(&[]))
        .unwrap();

    // 2. Regular file: /bin/busybox
    let busybox_content = b"#!/bin/busybox\necho busybox";
    let mut bb_header = Header::new_gnu();
    bb_header.set_entry_type(EntryType::Regular);
    bb_header.set_mode(0o755);
    bb_header.set_size(busybox_content.len() as u64);
    bb_header.set_cksum();
    tar_builder
        .append_data(&mut bb_header, "bin/busybox", Cursor::new(busybox_content))
        .unwrap();

    // 3. Symlink: /bin/sh -> /bin/busybox (Container absolute symlink)
    let mut sh_header = Header::new_gnu();
    sh_header.set_entry_type(EntryType::Symlink);
    sh_header.set_link_name("/bin/busybox").unwrap();
    sh_header.set_mode(0o777);
    sh_header.set_size(0);
    sh_header.set_cksum();
    tar_builder
        .append_data(&mut sh_header, "bin/sh", Cursor::new(&[]))
        .unwrap();

    // 4. Directory: /etc
    let mut etc_header = Header::new_gnu();
    etc_header.set_entry_type(EntryType::Directory);
    etc_header.set_mode(0o755);
    etc_header.set_size(0);
    etc_header.set_cksum();
    tar_builder
        .append_data(&mut etc_header, "etc/", Cursor::new(&[]))
        .unwrap();

    // 5. Regular file: /etc/os-release
    let os_release_content = b"NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.0\n";
    let mut os_header = Header::new_gnu();
    os_header.set_entry_type(EntryType::Regular);
    os_header.set_mode(0o644);
    os_header.set_size(os_release_content.len() as u64);
    os_header.set_cksum();
    tar_builder
        .append_data(
            &mut os_header,
            "etc/os-release",
            Cursor::new(os_release_content),
        )
        .unwrap();

    // 6. OCI Whiteout marker: etc/.wh.hosts (deleting hosts file from lower layer)
    let mut wh_header = Header::new_gnu();
    wh_header.set_entry_type(EntryType::Regular);
    wh_header.set_mode(0o644);
    wh_header.set_size(0);
    wh_header.set_cksum();
    tar_builder
        .append_data(&mut wh_header, "etc/.wh.hosts", Cursor::new(&[]))
        .unwrap();

    // 7. OCI Opaque whiteout marker: var/cache/.wh..wh..opq (clearing directory from lower layers)
    let mut opq_header = Header::new_gnu();
    opq_header.set_entry_type(EntryType::Regular);
    opq_header.set_mode(0o644);
    opq_header.set_size(0);
    opq_header.set_cksum();
    tar_builder
        .append_data(&mut opq_header, "var/cache/.wh..wh..opq", Cursor::new(&[]))
        .unwrap();

    let tar_bytes = tar_builder.into_inner().unwrap();

    // Compress with Gzip as standard OCI image layer
    let mut gz_encoder = GzEncoder::new(Vec::new(), Compression::default());
    gz_encoder.write_all(&tar_bytes).unwrap();
    gz_encoder.finish().unwrap()
}

#[test]
fn test_alpine_layer_stream_processing_and_validation() {
    let layer_gz = build_alpine_layer_fixture();
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let safe_dir = SafeDir::open_rootfs(&rootfs).unwrap();

    // Open layer through ArchiveReader
    let (format, decompressed_reader) = ArchiveReader::open(Cursor::new(layer_gz), None).unwrap();
    assert_eq!(format, CompressionFormat::Gzip);

    let mut archive = tar::Archive::new(decompressed_reader);
    let entries = archive.entries().unwrap();

    let mut observed_entries = Vec::new();
    let mut whiteouts_detected = Vec::new();

    for entry_res in entries {
        let entry = entry_res.unwrap();
        let path = entry.path().unwrap().into_owned();

        // 1. Path sanitization check
        let _sanitized = sanitize_entry_path(&rootfs, &path).expect("Valid Alpine entry path");

        // 2. Whiteout detection check
        if let Some(whiteout) = Whiteout::parse(&path).unwrap() {
            whiteouts_detected.push(whiteout);
            continue;
        }

        // 3. Symlink target validation check
        if entry.header().entry_type().is_symlink() {
            let link_target = entry.link_name().unwrap().unwrap().into_owned();
            let link_parent = path.parent().unwrap_or_else(|| Path::new(""));
            let normalized = normalize_symlink_target(&rootfs, link_parent, &link_target)
                .expect("Valid container symlink");

            // Absolute container symlink "/bin/busybox" preserved
            assert_eq!(normalized, PathBuf::from("/bin/busybox"));
        }

        observed_entries.push(path.to_string_lossy().to_string());
    }

    // Verify observed entries
    assert!(observed_entries.contains(&"bin/".to_string()));
    assert!(observed_entries.contains(&"bin/busybox".to_string()));
    assert!(observed_entries.contains(&"bin/sh".to_string()));
    assert!(observed_entries.contains(&"etc/".to_string()));
    assert!(observed_entries.contains(&"etc/os-release".to_string()));

    // Verify whiteouts
    assert_eq!(whiteouts_detected.len(), 2);
    assert_eq!(
        whiteouts_detected[0],
        Whiteout::Entry(PathBuf::from("etc/hosts"))
    );
    assert_eq!(
        whiteouts_detected[1],
        Whiteout::Opaque(PathBuf::from("var/cache"))
    );

    // Test SafeDir extraction primitives for these components
    safe_dir.mkdir_at(Path::new("bin"), 0o755).unwrap();
    assert!(rootfs.join("bin").is_dir());

    let mut file = safe_dir
        .open_file_at(
            Path::new("bin/busybox"),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o755,
        )
        .unwrap();
    file.write_all(b"#!/bin/busybox\necho busybox").unwrap();
    drop(file);

    safe_dir
        .symlink_at(Path::new("/bin/busybox"), Path::new("bin/sh"))
        .unwrap();
    assert!(safe_dir.is_symlink_at(Path::new("bin/sh")).unwrap());
}

#[test]
fn test_alpine_layer_with_malicious_traversal_rejected() {
    let mut tar_bytes = Vec::new();

    // Construct raw TAR header with malicious traversal filename bypassing Builder::append_data checks
    let mut header = Header::new_gnu();
    let name = b"../../../../etc/shadow";
    header.as_mut_bytes()[..name.len()].copy_from_slice(name);
    header.set_size(10);
    header.set_mode(0o644);
    header.set_cksum();

    tar_bytes.extend_from_slice(header.as_bytes());
    tar_bytes.extend_from_slice(b"evil_pass!\0\0\0\0\0\0"); // 16 bytes padded to block
    tar_bytes.extend_from_slice(&[0u8; 512 - 16]); // pad out to 512 block
    tar_bytes.extend_from_slice(&[0u8; 1024]); // tar end markers

    let rootfs = Path::new("/var/lib/tavik/rootfs");

    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    let mut entries = archive.entries().unwrap();
    let entry = entries.next().unwrap().unwrap();

    let path = entry.path().unwrap();
    let err = sanitize_entry_path(rootfs, &path).unwrap_err();
    assert!(matches!(err, ImageError::PathTraversal { .. }));
}

#[test]
fn test_alpine_rootfs_end_to_end_assembly() {
    use std::os::unix::fs::MetadataExt;
    use tavik_image::{Layer, RootfsBuilder};

    let temp = tempdir().unwrap();
    let dest_rootfs = temp.path().join("alpine_rootfs");

    // 1. Layer 0: Alpine Base Layer
    let mut tar0 = Builder::new(Vec::new());

    // /bin/busybox
    let mut h_bb = Header::new_gnu();
    h_bb.set_entry_type(EntryType::Regular);
    h_bb.set_mode(0o755);
    h_bb.set_size(14);
    h_bb.set_cksum();
    tar0.append_data(&mut h_bb, "bin/busybox", Cursor::new(b"busybox_binary"))
        .unwrap();

    // /bin/sh -> /bin/busybox
    let mut h_sh = Header::new_gnu();
    h_sh.set_entry_type(EntryType::Symlink);
    h_sh.set_link_name("/bin/busybox").unwrap();
    h_sh.set_size(0);
    h_sh.set_cksum();
    tar0.append_data(&mut h_sh, "bin/sh", Cursor::new(&[]))
        .unwrap();

    // /etc/os-release
    let os_content = b"NAME=\"Alpine Linux\"\nID=alpine\n";
    let mut h_os = Header::new_gnu();
    h_os.set_entry_type(EntryType::Regular);
    h_os.set_mode(0o644);
    h_os.set_size(os_content.len() as u64);
    h_os.set_cksum();
    tar0.append_data(&mut h_os, "etc/os-release", Cursor::new(os_content))
        .unwrap();

    // /etc/hosts (to be removed in layer 1)
    let hosts_content = b"127.0.0.1 localhost\n";
    let mut h_hosts = Header::new_gnu();
    h_hosts.set_entry_type(EntryType::Regular);
    h_hosts.set_mode(0o644);
    h_hosts.set_size(hosts_content.len() as u64);
    h_hosts.set_cksum();
    tar0.append_data(&mut h_hosts, "etc/hosts", Cursor::new(hosts_content))
        .unwrap();

    // /var/cache/apk/old_index (to be wiped by opaque whiteout in layer 1)
    let mut h_old = Header::new_gnu();
    h_old.set_entry_type(EntryType::Regular);
    h_old.set_mode(0o644);
    h_old.set_size(9);
    h_old.set_cksum();
    tar0.append_data(
        &mut h_old,
        "var/cache/apk/old_index",
        Cursor::new(b"old_index"),
    )
    .unwrap();

    let tar0_raw = tar0.into_inner().unwrap();
    let mut gz0 = GzEncoder::new(Vec::new(), Compression::default());
    gz0.write_all(&tar0_raw).unwrap();
    let l0_bytes = gz0.finish().unwrap();
    let l0_path = temp.path().join("layer0.tar.gz");
    std::fs::write(&l0_path, &l0_bytes).unwrap();
    let layer0 = Layer::new("sha256:layer0", &l0_path, l0_bytes.len() as u64);

    // 2. Layer 1: Alpine Modification Layer
    let mut tar1 = Builder::new(Vec::new());

    // Deletes /etc/hosts
    let mut h_wh = Header::new_gnu();
    h_wh.set_entry_type(EntryType::Regular);
    h_wh.set_size(0);
    h_wh.set_cksum();
    tar1.append_data(&mut h_wh, "etc/.wh.hosts", Cursor::new(&[]))
        .unwrap();

    // Opaque whiteout on /var/cache/apk
    let mut h_opq = Header::new_gnu();
    h_opq.set_entry_type(EntryType::Regular);
    h_opq.set_size(0);
    h_opq.set_cksum();
    tar1.append_data(&mut h_opq, "var/cache/apk/.wh..wh..opq", Cursor::new(&[]))
        .unwrap();

    // New cache index
    let mut h_new = Header::new_gnu();
    h_new.set_entry_type(EntryType::Regular);
    h_new.set_mode(0o644);
    h_new.set_size(9);
    h_new.set_cksum();
    tar1.append_data(
        &mut h_new,
        "var/cache/apk/new_index",
        Cursor::new(b"new_index"),
    )
    .unwrap();

    // Hard link /usr/bin/busybox pointing to /bin/busybox
    let mut h_hl = Header::new_gnu();
    h_hl.set_entry_type(EntryType::Link);
    h_hl.set_link_name("bin/busybox").unwrap();
    h_hl.set_mode(0o755);
    h_hl.set_size(0);
    h_hl.set_cksum();
    tar1.append_data(&mut h_hl, "usr/bin/busybox", Cursor::new(&[]))
        .unwrap();

    // /etc/alpine-release
    let mut h_rel = Header::new_gnu();
    h_rel.set_entry_type(EntryType::Regular);
    h_rel.set_mode(0o644);
    h_rel.set_size(6);
    h_rel.set_cksum();
    tar1.append_data(&mut h_rel, "etc/alpine-release", Cursor::new(b"3.20.0"))
        .unwrap();

    let tar1_raw = tar1.into_inner().unwrap();
    let mut gz1 = GzEncoder::new(Vec::new(), Compression::default());
    gz1.write_all(&tar1_raw).unwrap();
    let l1_bytes = gz1.finish().unwrap();
    let l1_path = temp.path().join("layer1.tar.gz");
    std::fs::write(&l1_path, &l1_bytes).unwrap();
    let layer1 = Layer::new("sha256:layer1", &l1_path, l1_bytes.len() as u64);

    // 3. Build rootfs with RootfsBuilder
    let builder = RootfsBuilder::new();
    let rootfs_result = builder
        .build_rootfs(&[layer0, layer1], &dest_rootfs)
        .unwrap();

    assert_eq!(rootfs_result, dest_rootfs);

    // 4. Assertions on assembled Alpine rootfs
    assert!(dest_rootfs.join("bin/busybox").is_file());
    assert_eq!(
        std::fs::read(dest_rootfs.join("bin/busybox")).unwrap(),
        b"busybox_binary"
    );
    assert_eq!(
        std::fs::metadata(dest_rootfs.join("bin/busybox"))
            .unwrap()
            .mode()
            & 0o777,
        0o755
    );

    // Symlink
    assert!(dest_rootfs.join("bin/sh").is_symlink());
    assert_eq!(
        std::fs::read_link(dest_rootfs.join("bin/sh")).unwrap(),
        Path::new("/bin/busybox")
    );

    // /etc/os-release
    assert_eq!(
        std::fs::read(dest_rootfs.join("etc/os-release")).unwrap(),
        os_content
    );

    // /etc/hosts removed by whiteout
    assert!(!dest_rootfs.join("etc/hosts").exists());

    // /var/cache/apk/old_index removed by opaque whiteout
    assert!(!dest_rootfs.join("var/cache/apk/old_index").exists());

    // /var/cache/apk/new_index present
    assert_eq!(
        std::fs::read(dest_rootfs.join("var/cache/apk/new_index")).unwrap(),
        b"new_index"
    );

    // Hard link /usr/bin/busybox shares inode with /bin/busybox
    let bb_meta = std::fs::metadata(dest_rootfs.join("bin/busybox")).unwrap();
    let hl_meta = std::fs::metadata(dest_rootfs.join("usr/bin/busybox")).unwrap();
    assert_eq!(bb_meta.ino(), hl_meta.ino());

    // /etc/alpine-release
    assert_eq!(
        std::fs::read(dest_rootfs.join("etc/alpine-release")).unwrap(),
        b"3.20.0"
    );
}
