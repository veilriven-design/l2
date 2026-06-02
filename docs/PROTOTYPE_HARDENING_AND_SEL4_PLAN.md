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
- Provide `l2 sel4-setup` command (current) that installs prerequisites (Microkit SDK tarball primary, host tools) and sets up a seL4/Microkit dev environment. Strong RHEL/Fedora + podman support, paced output, `--fast` for CI/old hardware, hardware-aware warnings.
- Official Microkit SDK 2.2.0 tarball as unambiguous recommended path (fast on-ramp even on vintage hardware).
- Generated `~/l2-sel4-workspace/README-l2-sel4.md` with permanent guidance. (Historical Docker `l2 setup` / container ideas superseded by the practical SDK-focused `l2 sel4-setup`.)

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

**Status (as of v0.4.4):** Phase 0 complete + Phase 1 enforcing active — real working observer (`L2_STRICT_SECCOMP_OBSERVE=1`) and enforcing filter (auto for strict-mcp/ransom-hardened, or `L2_STRICT_SECCOMP_ENFORCE=1`) install `SECCOMP_RET_LOG` + `SECCOMP_FILTER_FLAG_LOG` / KILL filters. Profiles loadable from traces via `l2 trace --analyze --output-profile` / `l2 harden --generate-seccomp`. Kernel audit logs for strict-family policies. See `src/sandbox.rs` for `try_install_seccomp_*` and policy-aware logic. `ransom-hardened` exercises the strictest path (no-net + extended NEVER).

Phase 1 enforcing is now active for strict-family policies (especially `strict-mcp`, the current main focus). The filter supports loading external trace-derived minimal profiles (generated via `l2 trace --analyze` + `l2 harden --generate-seccomp` or `l2 crypto` flows).

**Current highest-priority concrete work:** Mature the `l2 crypto` + `strict-mcp` (NSA May 2026 MCP sec design for AI automation) + `ransom-hardened` + `l2 harden` + `l2 audit --test` (CPG 2.0 etc.) + **NEW `l2 great-harden`** (supreme for aerospace/industrial/OT AI per NSA/CISA Dec 2025, higher assurance, gap closing, impenetrable servers per 2026 NSA AI/ML supply chain CSI Mar, MCP May, agentic Apr) path, with immediate next being direct consumability/operationalization of harden artifacts (add --apply + safe automated application of generated units/profiles; see GitHub #7 and ROADMAP). Continue trace collection under `strict-mcp` (and ransom-hardened for sims, great-harden for critical), curation of allowlists (policy-aware, incl. ransomware + AIO malware-cancer), expansion of concrete host hardening steps (AIBOM/SBOM for AI, CPG mappings), and end-to-end validation with the resistance demos (incl. `l2_malware_cancer_resistance_demo.c` for substrate AIO defense). `great-harden` adds aerospace-grade extreme (kernel lockdown etc.) for industrial complexes. Full alignment sweep to latest (to the hour) NSA/CISA 2026 complete.

Recent progress on this thread (trace + hardening UX):
- `l2 trace --policy strict-mcp` (and `ransom-hardened`) with `--enforce` and auto-paced output.
- `l2 crypto` for selecting/applying verified profiles (including hybrid) system-wide.
- `l2 harden --profile strict-mcp` (and `ransom-hardened`) with NSA/CISA/FBI-aligned (and ransomware-specific) concrete steps, network isolation, auto systemd units, seccomp generation, and json artifacts for `l2 audit --test`.
- `docs/examples/l2_ransomware_resistance_demo.c` + `l2_miasma_resistance_demo.c` + `l2_malware_cancer_resistance_demo.c` + full `ransom-hardened` / `great-harden` substrate path for ransomware + Miasma supply-chain worm + viruses + AIO malware-cancer (direct l2 substrate attack: state/trace/audit/crypto + ns/bpf escapes + git/pip/ELF) + l2 North-Star Containment grand demo containment validation.
- **NEW `l2 great-harden`**: supreme aerospace/industrial mode for higher assurance, advanced hardening, closing logic gaps, making servers impenetrable, achieving l2 North-Star Containment (great-harden policy + extreme lockdown + AIO substrate defense preps + grand demo).
- Improved runtime messaging, `sandbox::print_seccomp_trace_reminder()`, and policy-aware Landlock/seccomp (ransom-hardened is strictest).
- Better guidance on recommended first workloads and practical capture commands. See also the demo .c headers.

See `src/sandbox.rs`, `l2 sel4-setup --help`, the resistance demo, and the updated `ROADMAP.md` / `STATUS.md`.