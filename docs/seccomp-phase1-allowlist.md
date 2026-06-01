# seccomp Phase 1 Allowlist (Work in Progress)

This document tracks the data-driven curation of a minimal seccomp allowlist primarily for the `strict` and `strict-mcp` policy protocols (our current main focus).

`l2 harden` prepares the host/container environment. `strict-mcp` (via `l2 trace --policy strict-mcp` and `l2 exec --policy strict-mcp`) is the execution policy that consumes the hardened substrate.

**Goal**: Build and maintain tight, high-assurance seccomp profiles aligned with NSA/CISA/FBI guidance for agentic/AI/MCP workloads.

**Philosophy** (consistent with l2):
- Minimal allowlist only.
- Data-driven from real traces.
- Prefer breaking a few edge cases over allowing dangerous syscalls.
- Architecture-specific (start with x86_64 + aarch64).

## Current Status

- Phase 0 observer implemented and UX improved (v0.3.2+).
- Trace collection tooling in progress (`l2 trace` subcommand + helpers).
- No enforcing filter yet.

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

## Collected Traces

(Traces will be summarized here as we collect them)

### Example run (v0.3.2+)

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

Note: This allowlist is primarily exercised under the `strict` and `strict-mcp` policy protocols (our current main focus). `strict-mcp` currently maps to the same strong isolation base as `strict` but is the designated protocol for high-assurance MCP/tool workloads and will receive additional hardening rules over time.

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

- Run the starter workloads using the new `l2 trace` command.
- Capture and parse logs.
- Populate the draft allowlist above.
- Implement the enforcing filter once we have confidence in the list.

---

See also:
- `src/sandbox.rs` (current observer + future filter location)
- `ROADMAP.md`
- `docs/PROTOTYPE_HARDENING_AND_SEL4_PLAN.md` (original hardening plan)