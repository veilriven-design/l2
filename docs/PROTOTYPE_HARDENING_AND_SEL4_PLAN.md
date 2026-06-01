# Prototype Hardening (Linux Namespaces Phase)

## Enhancements to Implement

1. **seccomp filters**: Restrict syscalls in exec'ed processes and the l2-core using seccomp-bpf (via `seccomp` or `nix` crate in Rust). Allow only necessary calls.
2. **Landlock LSM**: Use Landlock for filesystem sandboxing on modern kernels (restrict FS access for isolated systems).
3. **Capability dropping**: Drop all capabilities except needed using `capng` or Rust equivalents; run with minimal privileges.
4. **User namespaces**: Full use of user namespaces for rootless isolation.
5. **Mount namespaces + read-only mounts** where possible.
6. **Strict policy enforcement**: Make 'strict' policy apply these by default.

## seL4 Hosting/Auto-Install Plan

### Short-term (Prototype)
- Provide `l2 setup` command that installs prerequisites and sets up a Docker-based seL4 dev environment.
- Docker image: `veilriven/l2-sel4-dev` containing seL4 toolchain, Microkit, Rust cross-compile, and l2 source.
- Users run `docker run -it veilriven/l2-sel4-dev` or `l2 setup-sel4` which pulls and configures.

### Medium-term
- Scripted build using seL4's `repo` tool or CMake-based build system.
- Pre-built Microkit applications with l2-core as a component.
- Binary distribution for common architectures (x86_64, aarch64) with verified hashes.

### Long-term
- Full seL4 integration where l2-substrate runs as a seL4 root task or user task with capabilities.
- Automated CI builds of seL4 + l2 images/VMs.
- Documentation and one-command installer for developers.

See SEL4_INTEGRATION.md for architecture details.

See [ROADMAP.md](../ROADMAP.md) for the current overall priorities. The sections below are historical context + detailed hardening notes.

**Status (as of v0.3.2):** Phase 0 complete — real working observer now installs a `SECCOMP_RET_LOG` + `SECCOMP_FILTER_FLAG_LOG` filter when `L2_STRICT_SECCOMP_OBSERVE=1` is set. Kernel audit logs are produced for every syscall under strict policy. See `src/sandbox.rs:try_install_seccomp_observer` and the function docs for exact usage + viewing instructions.

**Current highest-priority concrete work:** Trace collection from realistic workloads + curation of a minimal allowlist → implementation of the Phase 1 enforcing seccomp filter.

Recent progress on this thread (trace UX):
- Improved runtime messaging and documentation when `L2_STRICT_SECCOMP_OBSERVE=1` is active.
- Added `sandbox::print_seccomp_trace_reminder()` helper called during strict execs.
- Better guidance on recommended first workloads and practical capture commands.

See `src/sandbox.rs` and the updated `ROADMAP.md`.