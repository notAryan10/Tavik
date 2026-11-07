use tavik_security::{Capability, CapabilityMap, SecurityError};

#[test]
fn test_capability_parsing_and_names() {
    assert_eq!(
        CapabilityMap::from_name("CAP_CHOWN").unwrap(),
        Capability::CAP_CHOWN
    );
    assert_eq!(
        CapabilityMap::from_name("chown").unwrap(),
        Capability::CAP_CHOWN
    );
    assert_eq!(
        CapabilityMap::from_name("CAP_SYS_ADMIN").unwrap(),
        Capability::CAP_SYS_ADMIN
    );
    assert_eq!(
        CapabilityMap::from_name("sys_admin").unwrap(),
        Capability::CAP_SYS_ADMIN
    );
    assert_eq!(
        CapabilityMap::from_name("CAP_CHECKPOINT_RESTORE").unwrap(),
        Capability::CAP_CHECKPOINT_RESTORE
    );

    // Unknown capability
    match CapabilityMap::from_name("CAP_NONEXISTENT") {
        Err(SecurityError::UnknownCapability(name)) => assert_eq!(name, "CAP_NONEXISTENT"),
        other => panic!("Expected UnknownCapability, got {:?}", other),
    }
}

#[test]
fn test_capability_mask_roundtrip() {
    let caps = vec![
        Capability::CAP_CHOWN,
        Capability::CAP_NET_BIND_SERVICE,
        Capability::CAP_SYS_ADMIN,
        Capability::CAP_BPF,
    ];

    let mask = CapabilityMap::to_mask(caps.iter().copied());
    let expected = (1u64 << 0) | (1u64 << 10) | (1u64 << 21) | (1u64 << 39);
    assert_eq!(mask, expected);

    let roundtrip = CapabilityMap::from_mask(mask);
    assert_eq!(roundtrip, caps);
}

#[test]
fn test_parse_all_deduplicates_and_sorts() {
    let input = vec!["CAP_KILL", "cap_chown", "CAP_KILL", "sys_chroot"];
    let parsed = CapabilityMap::parse_all(input).unwrap();
    assert_eq!(
        parsed,
        vec![
            Capability::CAP_CHOWN,
            Capability::CAP_KILL,
            Capability::CAP_SYS_CHROOT,
        ]
    );
}

#[test]
fn test_read_cap_last_cap() {
    let last = CapabilityMap::read_cap_last_cap().unwrap();
    assert!(last >= 40, "Kernel cap_last_cap should be at least 40");
}
