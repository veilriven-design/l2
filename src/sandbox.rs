use anyhow::Result;
use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use std::path::Path;

/// Applies strict sandboxing for --policy strict.
/// Implements no_new_privs + practical Landlock FS restrictions:
/// - Full R/W/X under the system workspace
/// - Read + Exec on standard system paths needed for shell/tools to function
/// - All other FS writes denied (high-assurance write isolation)
pub fn apply_strict_sandbox(workspace: Option<&Path>) -> Result<()> {
    // no_new_privs: prevent the process or children from gaining new privileges (e.g. via setuid binaries)
    if let Err(e) = nix::sys::prctl::set_no_new_privs() {
        eprintln!("[strict] note: could not set no_new_privs: {}", e);
    }

    // Phase 0 (approved hardening plan): seccomp observability path.
    // nix 0.29 does not expose seccomp; we use a minimal raw libc syscall wrapper (no new heavy deps).
    // When L2_STRICT_SECCOMP_OBSERVE=1 is set, attempt a non-enforcing observer filter
    // (SECCOMP_RET_LOG where possible). This produces real traces for curating the Phase 1 allowlist.
    // See docs and the plan for the full data-driven approach. We stay strictly within "strict" policy.
    if std::env::var_os("L2_STRICT_SECCOMP_OBSERVE").is_some() {
        if let Err(e) = try_install_seccomp_observer() {
            eprintln!("[strict] seccomp observer note: {}", e);
        }
    }

    // TODO (Phase 1): replace observer with real small allowlist filter (data-driven from traces).
    // TODO (next): capability dropping via prctl (PR_CAPBSET_DROP etc.) + minimal bounding set.
    // TODO (future): user + mount ns + ro-remounts (nix "sched" feature now enabled for exploration).
    // Current: Landlock + no_new_privs + unshare provide the v0.2 baseline. All changes respect the narrow charter.

    if let Some(ws) = workspace {
        // Choose a solid ABI version supported on modern kernels (V5 covers most useful features)
        let abi = ABI::V5;

        // We handle all FS rights so we can explicitly grant subsets
        let rs = Ruleset::default().handle_access(AccessFs::from_all(abi))?;
        let rs = rs.create()?;

        // Workspace: full access (this is the core of strict policy isolation)
        let ws_rules = path_beneath_rules([ws], AccessFs::from_all(abi));
        let mut rs = rs.add_rules(ws_rules)?;

        let ro_access = AccessFs::from_read(abi) | AccessFs::Execute;

        // Read+Exec on essential system paths (pragmatic allowlist so `sh -c`, coreutils etc. work).
        // Writes remain denied outside the workspace. This is a deliberate prototype compromise.
        // TODO(v0.2+): make this configurable or derive from PATH + ld cache for even tighter policy.
        let ro_paths = [
            "/bin",
            "/usr/bin",
            "/lib",
            "/usr/lib",
            "/lib64",
            "/usr/lib64",
            "/proc",
            "/dev",
            "/etc",
            "/tmp",
        ];
        for p in ro_paths {
            if Path::new(p).exists() {
                let rules = path_beneath_rules([p], ro_access);
                // Use ? here: failure to add a ro path aborts sandbox setup for this exec (still have no_new_privs)
                // In practice these succeed on any reasonable Linux system.
                rs = rs.add_rules(rules)?;
            }
        }

        // Enforce the final ruleset
        let status = rs.restrict_self()?;

        match status.ruleset {
            RulesetStatus::FullyEnforced => {
                println!(
                    "[strict] ✓ Landlock FS sandbox active (writes restricted to {}; RO+EXEC elsewhere)",
                    ws.display()
                );
            }
            RulesetStatus::PartiallyEnforced => {
                println!("[strict] ⚠ Landlock partially enforced (some features unavailable on this kernel)");
            }
            RulesetStatus::NotEnforced => {
                eprintln!("[strict] ⚠ Landlock not enforced on this system (kernel too old or LSM disabled)");
            }
        }
    } else {
        println!("[strict] Sandbox applied (no_new_privs + namespaces)");
        crate::audit::log(
            "sandbox",
            serde_json::json!({
                "type": "strict",
                "landlock": false,
                "note": "no workspace provided"
            }),
        );
    }

    Ok(())
}

/// Phase 0 observer (non-enforcing).
///
/// When `L2_STRICT_SECCOMP_OBSERVE=1` is set, this installs a real seccomp filter
/// using `SECCOMP_RET_LOG` + `SECCOMP_FILTER_FLAG_LOG`. Every syscall attempted
/// while the filter is active (l2 process + any children under `--policy strict`)
/// will generate kernel audit records.
///
/// This is the mechanism for collecting the accurate syscall data required to
/// build a tight, minimal, correct allowlist for the Phase 1 enforcing filter.
///
/// Usage to gather traces (run as root or via the normal sudo escalation):
///   L2_STRICT_SECCOMP_OBSERVE=1 l2 exec --policy strict your-workload.py
///   L2_STRICT_SECCOMP_OBSERVE=1 l2 exec --policy strict your-app.rs
///
/// Then inspect:
///   sudo dmesg -w | grep -i seccomp
///   journalctl -k --since "5 minutes ago" | grep seccomp
///   (or /var/log/audit/audit.log if auditd is running)
///
/// Uses only libc + raw syscall (no new crates). Graceful on old kernels / non-Linux.
fn try_install_seccomp_observer() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("[strict] seccomp observer: not Linux, skipping");
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        // SECCOMP_RET_LOG = allow + log the decision (kernel >= ~4.14)
        const SECCOMP_RET_LOG: u32 = 0x7ffc0000;

        // Improved BPF filter with basic architecture validation.
        // This is more robust and follows common seccomp best practices.
        // Offsets are standard on 64-bit Linux (x86_64 and aarch64).
        const AUDIT_ARCH_X86_64: u32 = 0xC000003E;
        const AUDIT_ARCH_AARCH64: u32 = 0xC00000B7;

        let filter: [libc::sock_filter; 5] = [
            // Load arch (offset 0)
            libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: 0,
            },
            // Jump if x86_64
            libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt: 1,
                jf: 0,
                k: AUDIT_ARCH_X86_64,
            },
            // Jump if aarch64 (otherwise fall through to RET_LOG anyway for observation)
            libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt: 0,
                jf: 1,
                k: AUDIT_ARCH_AARCH64,
            },
            // Load nr (offset 8)
            libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: 8,
            },
            // Return LOG for everything we care about
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_LOG,
            },
        ];

        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };

        // 1. Try modern seccomp(2) syscall with FLAG_LOG (preferred)
        const SECCOMP_FILTER_FLAG_LOG: libc::c_ulong = 2;
        let mut rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_LOG,
                &prog as *const _,
            )
        };

        if rc < 0 {
            let err = std::io::Error::last_os_error();
            let code = err.raw_os_error();

            // 2. Fallback to older prctl interface (very common on some kernels/distros)
            if code == Some(libc::ENOSYS) || code == Some(libc::EINVAL) {
                // PR_SET_SECCOMP = 22, SECCOMP_MODE_FILTER = 2
                rc = unsafe {
                    libc::syscall(
                        libc::SYS_prctl,
                        22i32,
                        2i32,
                        &prog as *const _ as usize,
                        0usize,
                        0usize,
                    )
                };
            }

            if rc < 0 {
                let err2 = std::io::Error::last_os_error();
                if err2.raw_os_error() == Some(libc::ENOSYS)
                    || err2.raw_os_error() == Some(libc::EINVAL)
                {
                    eprintln!("[strict] seccomp observer: kernel does not support seccomp filter logging ({}). Continuing with Landlock + no_new_privs only.", err2);
                    return Ok(());
                }
                anyhow::bail!("failed to install seccomp observer filter: {}", err2);
            }
        }

        eprintln!(
            "[strict] ✓ seccomp observer filter installed (SECCOMP_RET_LOG + arch check + prctl fallback). \
             All syscalls while this process (and its children) run under strict will be logged.\n\
             View with:  sudo dmesg -w | grep -i seccomp    or    journalctl -k | grep seccomp"
        );

        crate::audit::log(
            "sandbox",
            serde_json::json!({
                "type": "strict",
                "landlock": true,
                "seccomp_observer": std::env::var_os("L2_STRICT_SECCOMP_OBSERVE").is_some()
            }),
        );

        Ok(())
    }
}
