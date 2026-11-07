use crate::error::SecurityError;
use crate::seccomp::action::SeccompAction;
use crate::seccomp::architecture::SeccompArchitecture;
use crate::seccomp::argument::{SeccompArg, SeccompOperator};
use crate::seccomp::syscall::SyscallResolver;
use crate::seccomp::SeccompProfile;

/// Maximum number of BPF instructions allowed by the Linux kernel.
pub const BPF_MAXINSNS: usize = 4096;

// BPF instruction classes
const BPF_LD: u16 = 0x00;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;

// BPF size modifiers
const BPF_W: u16 = 0x00;

// BPF mode modifiers
const BPF_ABS: u16 = 0x20;

// BPF jump operators
const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;

// BPF ALU operators
const BPF_AND: u16 = 0x50;

// BPF source modifiers
const BPF_K: u16 = 0x00;

// Offsets in struct seccomp_data
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;

/// Classic BPF filter instruction (equivalent to Linux `struct sock_filter`).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// BPF program container (equivalent to Linux `struct sock_fprog`).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

/// Pure-Rust compiler translating OCI `SeccompProfile` into classic BPF bytecode (`SockFilter`).
pub struct SeccompCompiler;

impl SeccompCompiler {
    /// Compiles an OCI SeccompProfile for a specific target architecture into a validated BPF program.
    pub fn compile(
        profile: &SeccompProfile,
        target_arch: SeccompArchitecture,
    ) -> Result<Vec<SockFilter>, SecurityError> {
        // 1. Validate profile integrity
        profile.validate()?;

        // 2. Validate target architecture against profile's declared architectures if specified
        if !profile.architectures.is_empty() && !profile.architectures.contains(&target_arch) {
            return Err(SecurityError::UnsupportedArchitecture(format!(
                "Target architecture {} is not permitted by seccomp profile",
                target_arch
            )));
        }

        let mut insns = Vec::new();

        // 3. Emit Architecture Check:
        // Load seccomp_data.arch
        insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
        // Jump if arch == target_arch.audit_arch(), else jump to arch-mismatch default action
        // Placeholder jump: we will fix up the false jump offset after assembling
        let arch_jmp_idx = insns.len();
        insns.push(bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            target_arch.audit_arch(),
            0,
            0,
        ));

        // 4. Load syscall number: seccomp_data.nr
        insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

        // 5. Sort rules by action precedence to ensure deterministic evaluation
        let mut sorted_rules = profile.syscalls.clone();
        sorted_rules.sort_by_key(|r| action_precedence(r.action));

        // 6. Generate syscall rules
        // For each rule, generate matches
        for rule in &sorted_rules {
            let mut resolved_syscalls = Vec::new();
            for name in &rule.names {
                let nr = SyscallResolver::resolve(target_arch, name)?;
                if !resolved_syscalls.contains(&nr) {
                    resolved_syscalls.push(nr);
                }
            }

            for syscall_nr in resolved_syscalls {
                // If the rule has no arguments: simple direct jump on match
                if rule.args.is_empty() {
                    let ret_val = rule
                        .action
                        .bpf_ret_value(rule.errno_ret.or(profile.default_errno_ret));
                    // JEQ syscall_nr -> jt: 0 (match: fall through to execute ret_val immediately),
                    //                   jf: 1 (no match: skip ret_val to evaluate next rule/default)
                    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 1));
                    insns.push(bpf_stmt(BPF_RET | BPF_K, ret_val));
                } else {
                    // Rule with argument conditions:
                    // If syscall == syscall_nr: proceed to evaluate argument conditions
                    // Else: jump over argument evaluation block
                    let syscall_chk_idx = insns.len();
                    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 0));

                    let _arg_start = insns.len();
                    let mut mismatch_jumps = Vec::new();

                    for arg in &rule.args {
                        compile_argument_condition(arg, &mut insns, &mut mismatch_jumps)?;
                    }

                    // If all arguments matched: return rule action
                    let ret_val = rule
                        .action
                        .bpf_ret_value(rule.errno_ret.or(profile.default_errno_ret));
                    insns.push(bpf_stmt(BPF_RET | BPF_K, ret_val));

                    // Reload syscall number in accumulator A in case argument evaluation modified A
                    let reload_idx = insns.len();
                    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

                    // Fix up the syscall mismatch jump to target the reload instruction
                    let jf_offset = (reload_idx - syscall_chk_idx - 1) as u8;
                    insns[syscall_chk_idx].jf = jf_offset;

                    // Fix up all argument mismatch jumps to target the reload instruction
                    for jump_idx in mismatch_jumps {
                        let offset = (reload_idx - jump_idx - 1) as u8;
                        // Determine whether to patch jt or jf based on instruction opcode
                        if insns[jump_idx].jf == 0xFF {
                            insns[jump_idx].jf = offset;
                        } else if insns[jump_idx].jt == 0xFF {
                            insns[jump_idx].jt = offset;
                        }
                    }
                }
            }
        }

        // 7. Emit Default Action Return
        let default_ret_idx = insns.len();
        let default_ret_val = profile
            .default_action
            .bpf_ret_value(profile.default_errno_ret);
        insns.push(bpf_stmt(BPF_RET | BPF_K, default_ret_val));

        // 8. Fix up initial architecture mismatch jump to point to default action
        let arch_jf_offset = (default_ret_idx - arch_jmp_idx - 1) as u8;
        insns[arch_jmp_idx].jf = arch_jf_offset;

        // 9. Enforce maximum program size limit
        if insns.len() > BPF_MAXINSNS {
            return Err(SecurityError::SeccompProgramTooLarge {
                len: insns.len(),
                max: BPF_MAXINSNS,
            });
        }

        // 10. Validate program integrity (validate all jump boundaries)
        validate_bpf_program(&insns)?;

        Ok(insns)
    }
}

/// Linux seccomp action precedence ordering (highest precedence first).
fn action_precedence(action: SeccompAction) -> u8 {
    match action {
        SeccompAction::KillProcess => 0,
        SeccompAction::KillThread | SeccompAction::Kill => 1,
        SeccompAction::Trap => 2,
        SeccompAction::Errno => 3,
        SeccompAction::Notify => 4,
        SeccompAction::Trace => 5,
        SeccompAction::Log => 6,
        SeccompAction::Allow => 7,
    }
}

/// Compiles a 64-bit argument comparison condition into BPF instructions.
/// Uses 32-bit word loads for little-endian architectures.
fn compile_argument_condition(
    arg: &SeccompArg,
    insns: &mut Vec<SockFilter>,
    mismatch_jumps: &mut Vec<usize>,
) -> Result<(), SecurityError> {
    arg.validate()?;

    let low_offset = SECCOMP_DATA_ARGS_OFFSET + (arg.index * 8);
    let high_offset = low_offset + 4;

    let val_low = (arg.value & 0xFFFF_FFFF) as u32;
    let val_high = (arg.value >> 32) as u32;

    match arg.op {
        SeccompOperator::Equal => {
            // High word must equal val_high
            insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, high_offset));
            let jmp_high = insns.len();
            insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, val_high, 0, 0xFF));
            mismatch_jumps.push(jmp_high);

            // Low word must equal val_low
            insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, low_offset));
            let jmp_low = insns.len();
            insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, val_low, 0, 0xFF));
            mismatch_jumps.push(jmp_low);
        }

        SeccompOperator::NotEqual => {
            // High word != val_high => condition satisfied, skip low word check
            insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, high_offset));
            let _jmp_high = insns.len();
            // jt: 2 (skip low word load & test), jf: 0 (fall through to low word check)
            insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, val_high, 0, 2));

            // High word was equal, so check low word != val_low
            insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, low_offset));
            let jmp_low = insns.len();
            // JEQ val_low: if equal, mismatch! (jf: 0xFF)
            insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, val_low, 0xFF, 0));
            mismatch_jumps.push(jmp_low);
        }

        SeccompOperator::GreaterThan => {
            // arg > value
            insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, high_offset));
            // If high > val_high: success! (jump over low check to next arg)
            let _jmp_gt = insns.len();
            insns.push(bpf_jump(BPF_JMP | BPF_JGT | BPF_K, val_high, 3, 0));

            // If high == val_high: continue to low check, else mismatch
            let jmp_eq = insns.len();
            insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, val_high, 0, 0xFF));
            mismatch_jumps.push(jmp_eq);

            // High words are equal: check low > val_low
            insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, low_offset));
            let jmp_low = insns.len();
            insns.push(bpf_jump(BPF_JMP | BPF_JGT | BPF_K, val_low, 0, 0xFF));
            mismatch_jumps.push(jmp_low);
        }

        SeccompOperator::GreaterOrEqual => {
            // arg >= value
            insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, high_offset));
            // If high > val_high: success!
            let _jmp_gt = insns.len();
            insns.push(bpf_jump(BPF_JMP | BPF_JGT | BPF_K, val_high, 3, 0));

            // If high == val_high: continue to low check, else mismatch
            let jmp_eq = insns.len();
            insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, val_high, 0, 0xFF));
            mismatch_jumps.push(jmp_eq);

            // High words are equal: check low >= val_low
            insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, low_offset));
            let jmp_low = insns.len();
            insns.push(bpf_jump(BPF_JMP | BPF_JGE | BPF_K, val_low, 0, 0xFF));
            mismatch_jumps.push(jmp_low);
        }

        SeccompOperator::LessThan => {
            // arg < value
            insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, high_offset));
            // If high > val_high: mismatch!
            let jmp_gt = insns.len();
            insns.push(bpf_jump(BPF_JMP | BPF_JGT | BPF_K, val_high, 0xFF, 0));
            mismatch_jumps.push(jmp_gt);

            // If high < val_high (not equal): success!
            let _jmp_eq = insns.len();
            insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, val_high, 0, 3));

            // High words are equal: check low < val_low (i.e. low >= val_low is mismatch)
            insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, low_offset));
            let jmp_low = insns.len();
            insns.push(bpf_jump(BPF_JMP | BPF_JGE | BPF_K, val_low, 0xFF, 0));
            mismatch_jumps.push(jmp_low);
        }

        SeccompOperator::LessOrEqual => {
            // arg <= value
            insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, high_offset));
            // If high > val_high: mismatch!
            let jmp_gt = insns.len();
            insns.push(bpf_jump(BPF_JMP | BPF_JGT | BPF_K, val_high, 0xFF, 0));
            mismatch_jumps.push(jmp_gt);

            // If high < val_high (not equal): success!
            let _jmp_eq = insns.len();
            insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, val_high, 0, 3));

            // High words are equal: check low <= val_low (i.e. low > val_low is mismatch)
            insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, low_offset));
            let jmp_low = insns.len();
            insns.push(bpf_jump(BPF_JMP | BPF_JGT | BPF_K, val_low, 0xFF, 0));
            mismatch_jumps.push(jmp_low);
        }

        SeccompOperator::MaskedEqual => {
            // (arg & value_two) == (value & value_two)
            let mask = arg.value_two;
            let expected = arg.value & mask;

            let mask_low = (mask & 0xFFFF_FFFF) as u32;
            let mask_high = (mask >> 32) as u32;

            let exp_low = (expected & 0xFFFF_FFFF) as u32;
            let exp_high = (expected >> 32) as u32;

            // 1. High word
            insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, high_offset));
            insns.push(bpf_stmt(BPF_ALU | BPF_AND | BPF_K, mask_high));
            let jmp_high = insns.len();
            insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, exp_high, 0, 0xFF));
            mismatch_jumps.push(jmp_high);

            // 2. Low word
            insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, low_offset));
            insns.push(bpf_stmt(BPF_ALU | BPF_AND | BPF_K, mask_low));
            let jmp_low = insns.len();
            insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, exp_low, 0, 0xFF));
            mismatch_jumps.push(jmp_low);
        }
    }

    Ok(())
}

/// Validates that all jumps in the compiled BPF program land within valid program instruction bounds.
fn validate_bpf_program(insns: &[SockFilter]) -> Result<(), SecurityError> {
    let len = insns.len();
    for (i, insn) in insns.iter().enumerate() {
        let class = insn.code & 0x07;
        if class == BPF_JMP {
            let op = insn.code & 0xf0;
            if op == BPF_JA {
                let target = i + 1 + (insn.k as usize);
                if target >= len {
                    return Err(SecurityError::SeccompCompilationError(format!(
                        "Invalid unconditional jump at index {}: target {} exceeds program length {}",
                        i, target, len
                    )));
                }
            } else {
                let jt_target = i + 1 + (insn.jt as usize);
                let jf_target = i + 1 + (insn.jf as usize);
                if jt_target >= len {
                    return Err(SecurityError::SeccompCompilationError(format!(
                        "Invalid jump_true at index {}: target {} exceeds program length {}",
                        i, jt_target, len
                    )));
                }
                if jf_target >= len {
                    return Err(SecurityError::SeccompCompilationError(format!(
                        "Invalid jump_false at index {}: target {} exceeds program length {}",
                        i, jf_target, len
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Helper to create a BPF statement (jt = 0, jf = 0).
const fn bpf_stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

/// Helper to create a BPF conditional jump instruction.
const fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}
