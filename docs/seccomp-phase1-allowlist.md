# seccomp Phase 1 Allowlist (Work in Progress)

This document tracks the data-driven curation of a minimal seccomp allowlist primarily for the `strict`, `strict-mcp`, and `ransom-hardened` (full safety / ransomware testing) policy protocols.

`l2 harden` prepares the host/container environment. `strict-mcp` (via `l2 trace --policy strict-mcp` and `l2 exec --policy strict-mcp`) is the execution policy that consumes the hardened substrate.

**Goal**: Build and maintain tight, high-assurance seccomp profiles aligned with NSA/CISA/FBI guidance for agentic/AI/MCP workloads.

**Philosophy** (consistent with l2):
- Minimal allowlist only.
- Data-driven from real traces.
- Prefer breaking a few edge cases over allowing dangerous syscalls.
- Architecture-specific (start with x86_64 + aarch64).

## Current Status

- Phase 0 observer + Phase 1 enforcing filter fully implemented and integrated (v0.4.0+).
- `l2 trace --policy <p>` (strict / strict-mcp / ransom-hardened) + `--analyze <log> --output-profile` produces minimal loadable profiles.
- `l2 harden --generate-seccomp` and runtime auto-discovery (for strict-mcp/ransom-hardened) wire profiles directly.
- Enforcing active by default for `strict-mcp` and `ransom-hardened` (full safety); `L2_STRICT_SECCOMP_ENFORCE=1` for others. NEVER_ALLOWED blacklist always hard-enforced.
- `ransom-hardened` uses tiniest allowlist + extended net/ptrace/modules blacklist for ransomware containment testing (paired with `l2_ransomware_resistance_demo.c`).

## Methodology

1. Run representative workloads under `L2_STRICT_SECCOMP_OBSERVE=1 l2 trace ...` (or the env var directly).
2. Capture logs via `dmesg`, `journalctl -k`, or `ausearch`.
3. Extract unique syscall numbers + arch.
4. Curate allowlist.
5. Implement enforcing filter in `src/sandbox.rs`.
6. Iterate.

## Recommended Starter Workloads

- Basic shell: `sh -c 'ls; cat /etc/passwd | head -3; echo hello'`
- Python: `python3 -c "print('hello'); import os; os.listdir('.')"`
- Rust compilation (very useful): `cargo build --quiet` inside a system with a small Rust project
- Common tools: `git status`, `make`, `curl -I https://example.com`, `find . -type f | head -5`
- Interpreters: Node/Ruby if available in the environment
- For `ransom-hardened` (full safety): the `l2_ransomware_resistance_demo.c` (WannaCry-class) or `l2_miasma_resistance_demo.c` (Miasma supply-chain npm worm: preinstall + OIDC exfil + repack + "Miasma: The Spreading Blight" propagation) under `L2_STRICT_SECCOMP_ENFORCE=1 l2 trace --policy ransom-hardened`. Expect zero net syscalls (41/42/...), ptrace etc. — those must stay in NEVER_ALLOWED. Supply-chain worms add emphasis on blocking package cache writes (Landlock) + token exfil (env clear + no net).

## Collected Traces

(Traces will be summarized here as we collect them)

### Example run (v0.4.0+)

```bash
L2_STRICT_SECCOMP_OBSERVE=1 l2 trace --policy strict sh -c 'echo hello; ls /proc | head -3'
# or using the new convenience:
l2 trace sh -c 'echo hello; ls'
```

Capture:
```bash
journalctl -k --since "1 min ago" | grep seccomp > trace1.log
l2 trace --analyze trace1.log
```

Add the resulting syscall numbers to the draft allowlist below.

### Example Trace Summary Format

```
arch=x86_64
syscalls:
  0 read
  1 write
  2 open
  ...
```

## Draft Allowlist (x86_64) — Initial Seed

**Status**: Seeded from common knowledge + early analyzer tests. Needs real trace data.

Note: This allowlist is exercised under the `strict`, `strict-mcp` (main focus for agentic/MCP), and `ransom-hardened` (full safety / ransomware + Miasma supply-chain worm testing) policy protocols. `strict-mcp` and `ransom-hardened` receive per-protocol tightening (ransom-hardened is the strictest: workspace-only + no net/ptrace etc. to stop credential exfil and npm worm spread). Profiles are data-driven from `l2 trace` under the target policy. Use the miasma and ransomware demos for validation.

From analyzer test run (sample log):
- 0 (read)
- 1 (write)
- 3 (close)
- 59 (execve)
- 257 (openat)

Common syscalls needed for basic shell + tool workloads (to be validated with real traces):

**Core I/O & Files**
- 0 read
- 1 write
- 3 close
- 8 lseek
- 9 mmap
- 10 mprotect
- 11 munmap
- 12 brk
- 16 ioctl (careful)
- 257 openat
- 262 newfstatat / fstatat64
- 270 pselect6

**Process / Execution**
- 59 execve
- 60 exit
- 231 exit_group
- 39 getpid
- 186 gettid
- 202 futex
- 228 clock_gettime
- 234 tgkill (for some languages)
- 435 clone3 (modern kernels)

**Directory / FS traversal**
- 78 getdents64
- 79 getcwd

**Signal / Misc**
- 13 rt_sigaction
- 14 rt_sigprocmask
- 15 rt_sigreturn
- 186 gettid
- 435 clone3

**Architecture specific**
- 158 arch_prctl (x86_64)
- 424 pidfd_open (newer)

**Strongly avoid in strict** (unless explicitly granted):
- ptrace, process_vm_readv/writev, init_module, finit_module, kexec_load, reboot, swapon, etc.

Next step: Run real workloads with `l2 trace` and feed the logs through `--analyze` to validate / expand this list.

## Next Actions

- Run the starter workloads using `l2 trace --policy strict-mcp` (or `ransom-hardened` for sims) with `--output-profile` for direct use.
- Capture and parse logs (supports journalctl, dmesg, etc.).
- Populate/curate the draft allowlist (policy-specific variants).
- Use `l2 trace --analyze ... --output-profile ~/.l2/seccomp/strict-mcp.txt` (or ransom...) + `l2 harden --generate-seccomp` + `l2 audit --test` for closed-loop hardening.
- `ransom-hardened` + demo.c is the validation workload for full safety (expect no net/encrypt/persist escapes).

The enforcing filter (Phase 1) + auto profile discovery + cap drop + per-policy Landlock + `l2 audit --test` (harden json) are now implemented and integrated with strict-mcp and ransom-hardened. See also `docs/examples/l2_ransomware_resistance_demo.c`.

---

See also:
- `src/sandbox.rs` (observer + enforcing filter + policy dispatch for strict-mcp/ransom-hardened)
- `ROADMAP.md`, `STATUS.md`, `SECURITY.md`
- `docs/PROTOTYPE_HARDENING_AND_SEL4_PLAN.md` (hardening plan)
- `docs/examples/l2_ransomware_resistance_demo.c` (use under ransom-hardened for validation)