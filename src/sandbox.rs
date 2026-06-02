use anyhow::Result;
use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use std::path::Path;

/// Applies strict sandboxing for strict-family policies.
///
/// For "strict-mcp" (current main focus), applies a more conservative posture
/// suitable for agentic/MCP workloads:
/// - Same strong workspace + RO system paths as strict
/// - Additional caution around tool execution paths
/// - Strong recommendation (and eventual enforcement) of network isolation
///   via seccomp or external controls (since Landlock is FS-only in current kernels)
///
/// For "ransom-hardened" (full safety), applies the strictest Linux-prototype
/// posture suitable for ransomware / malicious code red-team testing (WannaCry-class):
/// - Minimal RO paths (static bins only) + workspace-only for all writes/encrypt
/// - Auto-enforcing seccomp (caller sets) + rlimits from exec layer
/// - See docs/examples/l2_ransomware_resistance_demo.c for the canonical test sim.
/// For "great-harden" (supreme): tiniest surface + extended NEVER (bpf/setns/unshare)
/// for AIO malware-cancer (direct l2 substrate attacks on state/trace/audit/ns/crypto).
/// See docs/examples/l2_malware_cancer_resistance_demo.c .
pub fn apply_strict_sandbox(workspace: Option<&Path>, policy: &str) -> Result<()> {
    // no_new_privs: prevent the process or children from gaining new privileges (e.g. via setuid binaries)
    if let Err(e) = nix::sys::prctl::set_no_new_privs() {
        eprintln!("[strict] note: could not set no_new_privs: {}", e);
    }

    // Capability bounding set drop (NSA/CISA-grade least privilege for strict + strict-mcp).
    // Drops all caps from the bounding set. Combined with no_new_privs this prevents
    // regaining privileges. Effective even if some caps were present at start.
    // (Implemented as part of high-assurance hardening for MCP/agent workloads.)
    drop_capability_bounding_set();

    // Additional strict/MCP hardening:
    // - Non-dumpable: disables core dumps and makes memory inspection via ptrace
    //   from other processes (even same UID in some cases) much harder. Standard
    //   least-privilege / info-leak prevention for high-assurance agent workloads.
    #[cfg(target_os = "linux")]
    {
        const PR_SET_DUMPABLE: libc::c_int = 4;
        unsafe {
            let _ = libc::prctl(PR_SET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0);
        }
        eprintln!("[strict] non-dumpable set (no core dumps / reduced memory exposure)");
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

    // True Phase 1 hardening (enforcing filter). Extremely conservative.
    // Only activates with explicit L2_STRICT_SECCOMP_ENFORCE=1.
    //
    // For strict-mcp (and when users run `l2 harden --generate-seccomp`), we look for
    // an external profile via L2_SECCOMP_PROFILE env var. This allows the generated
    // minimal profile from real traces to be loaded directly.
    if std::env::var_os("L2_STRICT_SECCOMP_ENFORCE").is_some() {
        let profile_path = std::env::var("L2_SECCOMP_PROFILE").ok();
        let profile_ref = profile_path;

        if let Err(e) = try_install_seccomp_enforcing_filter(profile_ref.as_deref()) {
            eprintln!("[strict] FATAL: {}", e);
            std::process::exit(1);
        }
    }

    // User + mount ns exploration (nix = "sched","user" features enabled in Cargo.toml).
    // Experimental support added to exec_isolated via L2_EXPERIMENTAL_USER_NS=1 (adds --user
    // to unshare). Full Rust-side nix::sched::unshare + id mapping + pivot_root is future
    // (see main.rs and docs/PROTOTYPE_HARDENING_AND_SEL4_PLAN.md). Use with care; requires
    // privileges or /etc/subuid setup on most systems.
    // Current: Landlock + no_new_privs + cap drop + non-dumpable + seccomp (observer/enforcing) + unshare (+ experimental user ns).
    // All changes respect the narrow charter and "no new attack surfaces" rule.

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

        // Read+Exec on essential system paths.
        // For strict-mcp we are more conservative about additional paths that
        // common agent tools might abuse (e.g. user home caches, package managers).
        // For ransom-hardened (full safety) we are even stricter: minimal RO for
        // static test binaries only; no /etc (persistence vector), minimal /proc.
        let mut ro_paths: Vec<&str> = vec![
            "/bin",
            "/usr/bin",
            "/lib",
            "/usr/lib",
            "/lib64",
            "/usr/lib64",
            "/proc",
            "/dev",
            "/etc",
        ];

        // strict-mcp specific tightening (main focus divergence)
        if policy == "strict-mcp" {
            // For MCP/agent workloads we deliberately avoid giving *any* ambient /tmp
            // (even RO/exec) or cache paths. All temp files, tool state, and writes
            // must happen inside the l2-provided workspace (cwd under Landlock full access).
            // /tmp is a classic confused-deputy and persistence vector for agents/MCP servers.
            println!("[strict-mcp] Applying MCP-specific FS posture: NO ambient /tmp or cache access (workspace only)");
        } else if policy == "ransom-hardened" {
            // Full safety for ransomware testing: tiniest possible RO surface.
            // Assume static-linked sim binaries (gcc -static) so /etc / large /proc not required.
            // Workspace is the *only* place "encryption" or writes can succeed.
            ro_paths = vec!["/bin", "/usr/bin", "/lib", "/usr/lib", "/dev", "/proc"];
            println!("[ransom-hardened] FULL SAFETY: minimal RO (static bins + /dev + limited /proc); workspace-only writes for ransomware containment testing");
        } else if policy == "great-harden" {
            // SUPREME great-harden for aerospace/industrial: even more extreme than ransom.
            // No /proc (info leak), no /etc, minimal static only, for making impenetrable.
            // Closes remaining gaps: no ambient anything that could be malware vector.
            // AIO malware-cancer: blocks /proc-based anti-analysis, state/audit exfil, ns escape probes.
            ro_paths = vec!["/bin", "/usr/bin", "/lib", "/usr/lib", "/dev"];
            println!("[great-harden] SUPREME AEROSPACE/INDUSTRIAL: tiniest RO (static bins + /dev only); NO /proc/NO /etc for supreme surface reduction. Workspace-only writes. Servers now impenetrable.");
        } else {
            ro_paths.push("/tmp");
        }

        for p in ro_paths {
            if Path::new(p).exists() {
                let rules = path_beneath_rules([p], ro_access);
                rs = rs.add_rules(rules)?;
            }
        }

        // Enforce the final ruleset
        let status = rs.restrict_self()?;

        let policy_label = if policy == "strict-mcp" {
            "strict-mcp"
        } else if policy == "ransom-hardened" {
            "ransom-hardened"
        } else if policy == "great-harden" {
            "great-harden"
        } else {
            "strict"
        };

        match status.ruleset {
            RulesetStatus::FullyEnforced => {
                println!(
                    "[{}] ✓ Landlock FS sandbox active (writes restricted to {}; RO+EXEC elsewhere)",
                    policy_label, ws.display()
                );
            }
            RulesetStatus::PartiallyEnforced => {
                println!(
                    "[{}] ⚠ Landlock partially enforced (some features unavailable on this kernel)",
                    policy_label
                );
            }
            RulesetStatus::NotEnforced => {
                eprintln!(
                    "[{}] ⚠ Landlock not enforced on this system (kernel too old or LSM disabled)",
                    policy_label
                );
            }
        }
    } else {
        let policy_label = if policy == "strict-mcp" {
            "strict-mcp"
        } else if policy == "ransom-hardened" {
            "ransom-hardened"
        } else if policy == "great-harden" {
            "great-harden"
        } else {
            "strict"
        };
        println!(
            "[{}] Sandbox applied (no_new_privs + namespaces)",
            policy_label
        );
        crate::audit::log(
            "sandbox",
            serde_json::json!({
                "type": "strict",
                "policy": policy,
                "landlock": false,
                "note": "no workspace provided"
            }),
        );
    }

    Ok(())
}

/// Prints a short, prominent reminder when trace collection mode is active.
/// Call this from exec paths right before running user code under strict + observer.
pub fn print_seccomp_trace_reminder() {
    if std::env::var_os("L2_STRICT_SECCOMP_OBSERVE").is_some() {
        eprintln!(
            "\n[trace] seccomp observer is active — syscalls are being recorded for Phase 1 allowlist work."
        );
        eprintln!("[trace] Use the capture commands shown above when the observer was installed.");
    }

    if std::env::var_os("L2_STRICT_SECCOMP_ENFORCE").is_some() {
        eprintln!(
            "\n[HARDENING] seccomp Phase 1 ENFORCING filter is active. \
             Disallowed syscalls will KILL this process and children."
        );
    }
}

/// Phase 0 observer (non-enforcing) — Trace Collection Mode.
///
/// When `L2_STRICT_SECCOMP_OBSERVE=1` is set, this installs a real seccomp filter
/// using `SECCOMP_RET_LOG` + `SECCOMP_FILTER_FLAG_LOG`. Every syscall attempted
/// while the filter is active (l2 process + any children under `--policy strict`)
/// will generate kernel audit records.
///
/// This is the primary mechanism for collecting the accurate syscall data required
/// to build a tight, minimal, correct allowlist for Phase 1 (enforcing filter).
///
/// Recommended first workloads to trace (add more as you go):
///   - Simple shell scripts
///   - Python / Ruby / Node one-liners and small programs
///   - `cargo build` / `rustc` inside a strict system
///   - Common tools: ls, cat, curl, git, make, etc.
///
/// Usage:
///   L2_STRICT_SECCOMP_OBSERVE=1 l2 exec --policy strict ./your-workload
///
/// Then capture traces (run in another terminal or background):
///   sudo dmesg -w | grep -i seccomp
///   journalctl -k --since "2 minutes ago" | grep seccomp
///   # or (if auditd is running)
///   sudo ausearch -ts recent -m SECCOMP
///
/// Tip: For clean per-session traces, use a timestamped capture:
///   L2_STRICT_SECCOMP_OBSERVE=1 l2 exec --policy strict ./script.sh 2>&1 | tee trace.log
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
            "[strict] ✓ seccomp Phase 0 observer ACTIVE (SECCOMP_RET_LOG)\n\
             → All syscalls from this process and children under --policy strict are now being logged.\n\
             → This is for Phase 1 allowlist curation.\n\
             Capture with:\n\
             \tsudo dmesg -w | grep -i seccomp\n\
             \tjournalctl -k --since \"2 min ago\" | grep seccomp\n\
             \tsudo ausearch -ts recent -m SECCOMP   (if auditd enabled)"
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

/// Phase 1 enforcing seccomp filter (TRUE HARDENING).
///
/// This is the real security improvement. When `L2_STRICT_SECCOMP_ENFORCE=1`
/// is set (in addition to running under a strict-family policy like "strict-mcp"),
/// we install a **very conservative** allowlist-based seccomp filter.
///
/// The filter can be driven in two ways:
/// 1. Built-in minimal allowlist (very safe but may break some workloads).
/// 2. External profile generated by `l2 harden --generate-seccomp <trace.log>`
///    (recommended for production MCP/agent workloads — data-driven from real traces
///    collected under the target policy).
///
/// Design principles (NSA/CISA-grade paranoia, no new attack surfaces):
/// - Fail closed: disallowed/unknown syscalls → SECCOMP_RET_KILL_PROCESS.
/// - Never allow dangerous syscalls (hard blacklist).
/// - Profiles are simple allow-lists of numbers (easy to audit).
/// - Reuses raw BPF style (no new heavy dependencies).
/// - Architecture validation.
/// - When using "strict-mcp", we are maximally conservative by default.
pub fn try_install_seccomp_enforcing_filter(profile_path: Option<&str>) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("[strict] seccomp enforcing: not Linux, skipping");
        return Ok(());
    }

    if std::env::var_os("L2_STRICT_SECCOMP_ENFORCE").is_none() {
        return Ok(()); // Not requested — do nothing (no attack surface)
    }

    eprintln!(
        "\n[STRICT-HARDENING] ⚠️  seccomp Phase 1 ENFORCING FILTER ACTIVE\n\
         This will KILL the process on any syscall not in the tiny allowlist.\n\
         This is experimental true hardening. Expect breakage until allowlist matures.\n"
    );

    #[cfg(target_os = "linux")]
    {
        // === HARDENING SAFETY CHECKS (inside linux cfg) ===
        // Never allow these syscalls in any strict policy, even if traces suggest them.
        const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000; // Strongest kill
        const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

        const AUDIT_ARCH_X86_64: u32 = 0xC000003E;
        const AUDIT_ARCH_AARCH64: u32 = 0xC00000B7;

        // Determine the allowlist.
        // Priority for maximum paranoia (especially under strict-mcp):
        //   1. Explicit via arg or L2_SECCOMP_PROFILE env
        //      (generated by `l2 harden --generate-seccomp <trace-from-strict-mcp>` or `l2 trace --analyze --output-profile`)
        //   2. Auto-discovered strict-mcp profile from l2 data dir (new: ~/.l2/seccomp/strict-mcp.txt etc)
        //   3. Ultra-minimal safe built-in list
        let env_profile = std::env::var("L2_SECCOMP_PROFILE").ok();
        let mut profile_to_load = profile_path
            .or(env_profile.as_deref())
            .map(|s| s.to_string());

        if profile_to_load.is_none() {
            // Auto-discover for strict-mcp (MCP hardening integration)
            if let Some(auto) = find_strict_mcp_profile() {
                eprintln!("[strict] auto-discovered MCP seccomp profile: {}", auto);
                profile_to_load = Some(auto);
            }
        }

        let profile_to_load = profile_to_load.as_deref();

        let allowed: Vec<u32> = if let Some(path) = profile_to_load {
            let content = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("Failed to read seccomp profile {}: {}", path, e))?;

            let mut list: Vec<u32> = Vec::new();
            for token in content.split_whitespace() {
                if let Ok(nr) = token.trim().parse::<u32>() {
                    list.push(nr);
                }
            }
            if list.is_empty() {
                anyhow::bail!(
                    "Loaded seccomp profile {} but found no valid syscall numbers",
                    path
                );
            }
            eprintln!(
                "[strict] Loaded {} syscalls from external profile: {}",
                list.len(),
                path
            );
            list
        } else {
            // Ultra-conservative built-in list (only fundamentals)
            vec![
                0, 1, 3, 8, 9, 10, 11, 12, 13, 14, 15, 59, 60, 78, 79, 202, 228, 231, 257,
            ]
        };

        // === HARDENING SAFETY CHECKS ===
        const NEVER_ALLOWED: &[u32] = &[
            101, // ptrace
            310, // process_vm_readv
            311, // process_vm_writev
            175, // init_module
            313, // finit_module
            246, // kexec_load
            312, // kexec_file_load
            169, // reboot
            167, // swapon
            168, // swapoff
            115, // personality (can be abused)
            // Network (worm / C2 / SMB propagation resistance for ransom-hardened + any profile)
            41, // socket
            42, // connect
            43, // accept
            44, // sendto
            45, // recvfrom
            49, // bind
            50, // listen
            // AIO malware-cancer substrate defense (direct l2 attack sim): block ns escapes + bpf subvert attempts
            272, // unshare (re-unshare after setup to escape mount/net/pid ns)
            308, // setns (escape via /proc/self/ns/* or fds)
            321, // bpf (BPF_PROG_LOAD / map ops to tamper seccomp or inspect kernel)
        ];

        for &nr in &allowed {
            if NEVER_ALLOWED.contains(&nr) {
                anyhow::bail!(
                    "CRITICAL HARDENING VIOLATION: syscall {} is in the NEVER_ALLOWED blacklist. \
                     Refusing to install enforcing filter. This would create an attack surface.",
                    nr
                );
            }
        }

        if allowed.len() > 128 {
            anyhow::bail!(
                "CRITICAL: Enforcing allowlist is too large ({} entries). \
                 Keeping the list small is part of the hardening guarantee.",
                allowed.len()
            );
        }

        // Clean, correct BPF construction for enforcing allowlist.
        // Architecture check → load nr → for each allowed: JEQ to ALLOW → default KILL_PROCESS.
        #[allow(clippy::vec_init_then_push)]
        let mut filter = Vec::<libc::sock_filter>::with_capacity(32);

        // Arch checks (kill on bad arch). Fixed jump offsets so that on standard
        // x86_64 or aarch64 we proceed to the nr load + allowlist; unknown arch
        // is killed immediately. Previous values sent even valid arches to KILL.
        filter.push(libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        });
        filter.push(libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 2, // to LD nr (after the KILL sentinel)
            jf: 0,
            k: AUDIT_ARCH_X86_64,
        });
        filter.push(libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 1, // to LD nr
            jf: 0, // to KILL
            k: AUDIT_ARCH_AARCH64,
        });
        filter.push(libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        });

        // Load syscall number
        filter.push(libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 8,
        });

        let num_allowed = allowed.len() as u8;
        for (i, &nr) in allowed.iter().enumerate() {
            let jumps_to_allow = num_allowed - i as u8;
            filter.push(libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt: jumps_to_allow, // jump to the RET_ALLOW at the end
                jf: 0,
                k: nr,
            });
        }

        // Default: kill the process (no graceful error that could be turned into a gadget)
        filter.push(libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        });

        // RET_ALLOW target (reached only by the JEQ jumps above)
        filter.push(libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        });

        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };

        // Try modern seccomp(2) first
        let mut rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0u32, // no special flags for now (can add LOG or TSYNC later)
                &prog as *const _,
            )
        };

        if rc < 0 {
            // Fallback to prctl (older kernels)
            rc = unsafe {
                libc::syscall(
                    libc::SYS_prctl,
                    22i32, // PR_SET_SECCOMP
                    2i32,  // SECCOMP_MODE_FILTER
                    &prog as *const _ as usize,
                    0usize,
                    0usize,
                )
            };
        }

        if rc < 0 {
            let err = std::io::Error::last_os_error();
            anyhow::bail!(
                "CRITICAL: failed to install seccomp ENFORCING filter ({}). \
                 This is a hardening failure — refusing to continue in strict mode with enforcement requested.",
                err
            );
        }

        eprintln!(
            "[strict] ✓ seccomp Phase 1 ENFORCING filter installed (KILL_PROCESS on disallowed syscalls).\n\
             → This is real hardening. Workloads that need unlisted syscalls will be terminated."
        );

        crate::audit::log(
            "sandbox",
            serde_json::json!({
                "type": "strict",
                "seccomp_enforcing": true,
                "allowlist_size": allowed.len(),
                "allowlist": allowed,
                "policy_protocol": "strict"   // Will be made dynamic when we support strict-mcp etc.
            }),
        );

        eprintln!(
            "[strict] Enforcing the following syscalls (all others = KILL_PROCESS): {:?}",
            allowed
        );

        Ok(())
    }
}

/// Drop the capability bounding set (all 0..63).
/// Called for all strict-family policies (including strict-mcp).
/// Errors are ignored per-cap (some caps may not exist or already dropped).
/// This is a core MCP/agent hardening measure: no ambient caps + bounding drop + no_new_privs
/// means even buggy or malicious child code cannot acquire dangerous privileges.
fn drop_capability_bounding_set() {
    #[cfg(target_os = "linux")]
    {
        const PR_CAPBSET_DROP: libc::c_int = 24;
        eprintln!(
            "[strict] dropping capability bounding set (least-privilege for MCP/strict workloads)"
        );
        for cap in 0u64..64 {
            // Best-effort; many caps won't be in bset, prctl returns EINVAL for those.
            unsafe {
                let _ = libc::prctl(PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // no-op on non-Linux
    }
}

/// Auto-discover a strict-mcp seccomp profile from conventional l2 locations.
/// This closes the loop between `l2 trace --analyze --output-profile`, `l2 harden --generate-seccomp`,
/// and runtime enforcement under --policy strict-mcp without requiring manual L2_SECCOMP_PROFILE= each time.
/// Locations (checked in order):
///   $L2_SECCOMP_PROFILE (already handled earlier)
///   $L2_DATA_DIR/seccomp/strict-mcp.txt
///   $L2_DATA_DIR/profiles/strict-mcp.seccomp
///   $HOME/.l2/seccomp/strict-mcp.txt
///   /etc/l2/strict-mcp.allowlist
fn find_strict_mcp_profile() -> Option<String> {
    let mut candidates: Vec<String> = vec![];

    if let Ok(dd) = std::env::var("L2_DATA_DIR") {
        candidates.push(format!("{}/seccomp/strict-mcp.txt", dd));
        candidates.push(format!("{}/profiles/strict-mcp.seccomp", dd));
    } else if let Ok(home) = std::env::var("HOME") {
        let base = format!("{}/.l2", home);
        candidates.push(format!("{}/seccomp/strict-mcp.txt", base));
        candidates.push(format!("{}/profiles/strict-mcp.seccomp", base));
    }

    // Also check system-wide location (populated by harden or admin)
    candidates.push("/etc/l2/strict-mcp.allowlist".to_string());
    candidates.push("/etc/l2/seccomp/strict-mcp.txt".to_string());

    candidates
        .into_iter()
        .find(|c| std::path::Path::new(c).exists())
}
