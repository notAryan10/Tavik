use tavik_security::seccomp::{
    SeccompAction, SeccompArchitecture, SeccompArg, SeccompCompiler, SeccompOperator,
    SeccompProfile, SyscallRule,
};
use tavik_security::SecurityError;

#[test]
fn test_compiler_emits_architecture_and_default_action() {
    let profile = SeccompProfile {
        default_action: SeccompAction::Errno,
        default_errno_ret: Some(1), // EPERM
        architectures: vec![SeccompArchitecture::Aarch64],
        flags: vec![],
        syscalls: vec![],
    };

    let bpf = SeccompCompiler::compile(&profile, SeccompArchitecture::Aarch64).unwrap();

    // Minimum program:
    // 0: LD [4] (arch)
    // 1: JEQ AUDIT_ARCH_AARCH64 (jt=0, jf=2)
    // 2: LD [0] (nr)
    // 3: RET ERRNO(1)
    assert!(bpf.len() >= 4);

    // Instruction 0: load arch
    assert_eq!(bpf[0].code, 0x20); // BPF_LD | BPF_W | BPF_ABS
    assert_eq!(bpf[0].k, 4);

    // Instruction 1: jump if arch == AArch64
    assert_eq!(bpf[1].code, 0x15); // BPF_JMP | BPF_JEQ | BPF_K
    assert_eq!(bpf[1].k, 0xC000_00B7);

    // Last instruction: default action return
    let last = bpf.last().unwrap();
    assert_eq!(last.code, 0x06); // BPF_RET | BPF_K
    assert_eq!(last.k, 0x0005_0001); // SECCOMP_RET_ERRNO | 1
}

#[test]
fn test_compiler_architecture_mismatch() {
    let profile = SeccompProfile {
        default_action: SeccompAction::Errno,
        default_errno_ret: None,
        architectures: vec![SeccompArchitecture::X86_64], // Only x86_64 declared
        flags: vec![],
        syscalls: vec![],
    };

    // Compiling for AArch64 should fail closed
    match SeccompCompiler::compile(&profile, SeccompArchitecture::Aarch64) {
        Err(SecurityError::UnsupportedArchitecture(_)) => {}
        other => panic!("Expected UnsupportedArchitecture error, got {:?}", other),
    }
}

#[test]
fn test_compiler_syscall_matching_and_or_semantics() {
    let profile = SeccompProfile {
        default_action: SeccompAction::Errno,
        default_errno_ret: Some(1),
        architectures: vec![SeccompArchitecture::Aarch64],
        flags: vec![],
        syscalls: vec![SyscallRule {
            names: vec!["read".to_string(), "write".to_string()], // OR semantics
            action: SeccompAction::Allow,
            errno_ret: None,
            args: vec![],
        }],
    };

    let bpf = SeccompCompiler::compile(&profile, SeccompArchitecture::Aarch64).unwrap();

    // On AArch64: read = 63, write = 64
    let has_read_check = bpf.iter().any(|i| i.k == 63);
    let has_write_check = bpf.iter().any(|i| i.k == 64);
    let has_allow_ret = bpf.iter().any(|i| i.code == 0x06 && i.k == 0x7fff_0000);

    assert!(has_read_check, "Missing read (63) check");
    assert!(has_write_check, "Missing write (64) check");
    assert!(has_allow_ret, "Missing ALLOW return instruction");
}

#[test]
fn test_compiler_64bit_argument_comparisons() {
    let operators = [
        SeccompOperator::Equal,
        SeccompOperator::NotEqual,
        SeccompOperator::GreaterThan,
        SeccompOperator::GreaterOrEqual,
        SeccompOperator::LessThan,
        SeccompOperator::LessOrEqual,
        SeccompOperator::MaskedEqual,
    ];

    for op in operators {
        let profile = SeccompProfile {
            default_action: SeccompAction::Errno,
            default_errno_ret: Some(1),
            architectures: vec![SeccompArchitecture::Aarch64],
            flags: vec![],
            syscalls: vec![SyscallRule {
                names: vec!["clone".to_string()],
                action: SeccompAction::Allow,
                errno_ret: None,
                args: vec![SeccompArg {
                    index: 0,
                    value: 0x1234_5678_9ABC_DEF0, // 64-bit value with distinct high/low
                    value_two: 0x0000_FFFF_FFFF_0000,
                    op,
                }],
            }],
        };

        let bpf = SeccompCompiler::compile(&profile, SeccompArchitecture::Aarch64).unwrap();
        assert!(
            bpf.len() >= 6,
            "Operator {:?} produced insufficient BPF instructions",
            op
        );

        // Verify low (16) and high (20) offset loads exist in generated BPF
        let has_low_load = bpf.iter().any(|i| i.code == 0x20 && i.k == 16);
        let has_high_load = bpf.iter().any(|i| i.code == 0x20 && i.k == 20);
        assert!(
            has_low_load,
            "Operator {:?} missing low word load at offset 16",
            op
        );
        assert!(
            has_high_load,
            "Operator {:?} missing high word load at offset 20",
            op
        );
    }
}

#[test]
fn test_compiler_multiple_arguments_and_semantics() {
    let profile = SeccompProfile {
        default_action: SeccompAction::Errno,
        default_errno_ret: Some(1),
        architectures: vec![SeccompArchitecture::Aarch64],
        flags: vec![],
        syscalls: vec![SyscallRule {
            names: vec!["prctl".to_string()],
            action: SeccompAction::Allow,
            errno_ret: None,
            args: vec![
                SeccompArg {
                    index: 0,
                    value: 38, // PR_SET_NO_NEW_PRIVS
                    value_two: 0,
                    op: SeccompOperator::Equal,
                },
                SeccompArg {
                    index: 1,
                    value: 1,
                    value_two: 0,
                    op: SeccompOperator::Equal,
                },
            ],
        }],
    };

    let bpf = SeccompCompiler::compile(&profile, SeccompArchitecture::Aarch64).unwrap();
    // Must load arg 0 (offset 16/20) and arg 1 (offset 24/28)
    assert!(bpf.iter().any(|i| i.k == 16));
    assert!(bpf.iter().any(|i| i.k == 24));
}

#[test]
fn test_compiler_unknown_syscall_fails_closed() {
    let profile = SeccompProfile {
        default_action: SeccompAction::Errno,
        default_errno_ret: None,
        architectures: vec![SeccompArchitecture::Aarch64],
        flags: vec![],
        syscalls: vec![SyscallRule {
            names: vec!["nonexistent_dangerous_syscall".to_string()],
            action: SeccompAction::Allow,
            errno_ret: None,
            args: vec![],
        }],
    };

    match SeccompCompiler::compile(&profile, SeccompArchitecture::Aarch64) {
        Err(SecurityError::UnknownSyscall(name)) => {
            assert_eq!(name, "nonexistent_dangerous_syscall");
        }
        other => panic!("Expected UnknownSyscall error, got {:?}", other),
    }
}
