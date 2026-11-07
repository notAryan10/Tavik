use tavik_security::seccomp::{
    SeccompAction, SeccompArchitecture, SeccompArg, SeccompFlag, SeccompOperator, SeccompProfile,
    SyscallRule,
};
use tavik_security::SecurityError;

#[test]
fn test_deserialize_aarch64_profile() {
    let json = r#"{
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": 1,
        "architectures": ["SCMP_ARCH_AARCH64"],
        "flags": ["SECCOMP_FILTER_FLAG_TSYNC"],
        "syscalls": [
            {
                "names": ["read", "write", "close"],
                "action": "SCMP_ACT_ALLOW"
            },
            {
                "names": ["reboot", "sys_kexec_load"],
                "action": "SCMP_ACT_ERRNO",
                "errnoRet": 1
            }
        ]
    }"#;

    let profile: SeccompProfile = serde_json::from_str(json).unwrap();
    profile.validate().unwrap();

    assert_eq!(profile.default_action, SeccompAction::Errno);
    assert_eq!(profile.default_errno_ret, Some(1));
    assert_eq!(profile.architectures, vec![SeccompArchitecture::Aarch64]);
    assert_eq!(profile.flags, vec![SeccompFlag::Tsync]);
    assert_eq!(profile.flags_mask(), 1);
    assert_eq!(profile.syscalls.len(), 2);
    assert_eq!(profile.syscalls[0].names, vec!["read", "write", "close"]);
    assert_eq!(profile.syscalls[0].action, SeccompAction::Allow);
    assert_eq!(profile.syscalls[1].names, vec!["reboot", "sys_kexec_load"]);
    assert_eq!(profile.syscalls[1].action, SeccompAction::Errno);
    assert_eq!(profile.syscalls[1].errno_ret, Some(1));
}

#[test]
fn test_deserialize_x86_64_profile() {
    let json = r#"{
        "defaultAction": "SCMP_ACT_ALLOW",
        "architectures": ["SCMP_ARCH_X86_64"],
        "syscalls": []
    }"#;

    let profile: SeccompProfile = serde_json::from_str(json).unwrap();
    profile.validate().unwrap();

    assert_eq!(profile.default_action, SeccompAction::Allow);
    assert_eq!(profile.architectures, vec![SeccompArchitecture::X86_64]);
    assert!(profile.syscalls.is_empty());
}

#[test]
fn test_all_actions_parsing_and_bpf_values() {
    let actions = [
        ("SCMP_ACT_KILL", SeccompAction::Kill, 0x0000_0000),
        (
            "SCMP_ACT_KILL_PROCESS",
            SeccompAction::KillProcess,
            0x8000_0000,
        ),
        (
            "SCMP_ACT_KILL_THREAD",
            SeccompAction::KillThread,
            0x0000_0000,
        ),
        ("SCMP_ACT_TRAP", SeccompAction::Trap, 0x0003_0000),
        ("SCMP_ACT_ERRNO", SeccompAction::Errno, 0x0005_0001), // default errno 1
        ("SCMP_ACT_TRACE", SeccompAction::Trace, 0x7ff0_0000),
        ("SCMP_ACT_LOG", SeccompAction::Log, 0x7ffc_0000),
        ("SCMP_ACT_NOTIFY", SeccompAction::Notify, 0x7fc0_0000),
        ("SCMP_ACT_ALLOW", SeccompAction::Allow, 0x7fff_0000),
    ];

    for (str_val, expected_act, expected_bpf) in actions {
        let parsed: SeccompAction = str_val.parse().unwrap();
        assert_eq!(parsed, expected_act);
        assert_eq!(parsed.bpf_ret_value(None), expected_bpf);

        // Serde roundtrip
        let json = format!("\"{}\"", str_val);
        let de: SeccompAction = serde_json::from_str(&json).unwrap();
        assert_eq!(de, expected_act);
    }

    // Errno with custom errnoRet
    assert_eq!(
        SeccompAction::Errno.bpf_ret_value(Some(13)), // EACCES
        0x0005_0000 | 13
    );
}

#[test]
fn test_all_operators_parsing() {
    let operators = [
        ("SCMP_CMP_NE", SeccompOperator::NotEqual),
        ("SCMP_CMP_LT", SeccompOperator::LessThan),
        ("SCMP_CMP_LE", SeccompOperator::LessOrEqual),
        ("SCMP_CMP_EQ", SeccompOperator::Equal),
        ("SCMP_CMP_GE", SeccompOperator::GreaterOrEqual),
        ("SCMP_CMP_GT", SeccompOperator::GreaterThan),
        ("SCMP_CMP_MASKED_EQ", SeccompOperator::MaskedEqual),
    ];

    for (str_val, expected_op) in operators {
        let parsed: SeccompOperator = str_val.parse().unwrap();
        assert_eq!(parsed, expected_op);

        // Serde roundtrip
        let json = format!("\"{}\"", str_val);
        let de: SeccompOperator = serde_json::from_str(&json).unwrap();
        assert_eq!(de, expected_op);
    }
}

#[test]
fn test_invalid_action_and_architecture() {
    assert!("SCMP_ACT_MAGIC".parse::<SeccompAction>().is_err());
    assert!("SCMP_ARCH_MIPS".parse::<SeccompArchitecture>().is_err());
    assert!("SCMP_CMP_UNKNOWN".parse::<SeccompOperator>().is_err());
}

#[test]
fn test_argument_index_validation() {
    let valid_arg = SeccompArg {
        index: 5,
        value: 100,
        value_two: 0,
        op: SeccompOperator::Equal,
    };
    assert!(valid_arg.validate().is_ok());

    let invalid_arg = SeccompArg {
        index: 6, // Beyond Linux limit of 0..=5
        value: 100,
        value_two: 0,
        op: SeccompOperator::Equal,
    };
    match invalid_arg.validate() {
        Err(SecurityError::InvalidConfiguration(msg)) => {
            assert!(msg.contains("index 6"));
        }
        other => panic!("Expected InvalidConfiguration error, got {:?}", other),
    }

    // Validating through rule and profile
    let rule = SyscallRule {
        names: vec!["clone".to_string()],
        action: SeccompAction::Allow,
        errno_ret: None,
        args: vec![invalid_arg],
    };
    let profile = SeccompProfile {
        default_action: SeccompAction::Errno,
        default_errno_ret: None,
        architectures: vec![],
        flags: vec![],
        syscalls: vec![rule],
    };
    assert!(profile.validate().is_err());
}

#[test]
fn test_empty_syscall_list_and_omitted_fields() {
    let minimal_json = r#"{
        "defaultAction": "SCMP_ACT_ALLOW"
    }"#;

    let profile: SeccompProfile = serde_json::from_str(minimal_json).unwrap();
    profile.validate().unwrap();

    assert_eq!(profile.default_action, SeccompAction::Allow);
    assert_eq!(profile.default_errno_ret, None);
    assert!(profile.architectures.is_empty());
    assert!(profile.flags.is_empty());
    assert!(profile.syscalls.is_empty());
}
