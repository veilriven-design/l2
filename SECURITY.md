# Security Model and Assurance Approach

l2 is designed for a **very high** threat model. The substrate must protect developer workflows and MCP operations against sophisticated adversaries, including supply-chain attacks, compromised host environments, and attempts to escape containment.

The terminal operator working through the narrow `l2` CLI/TUI is the only source of new authority. This is a core security property.

## Threat Model

- Adversaries may have code execution on the host operating system.
- MCP servers and other workloads running inside l2 may be malicious or compromised.
- Supply chain attacks against build tools, dependencies, or the host are in scope.
- Physical access and sophisticated side-channel or fault-injection attacks are out of scope for the initial design (future hardware platforms such as CHERI may change this).
- The goal is strong containment: a successful compromise of one workload inside l2 should not allow escape to other workloads or to the host except through explicitly authorized, narrow, auditable channels.

## Design Principles

1. **seL4 as the root of trust** — We rely on seL4's machine-checked isolation, capability, and integrity properties rather than attempting to re-verify a new kernel.
2. **Minimal userland TCB** — The code that runs with authority to create or manage systems must be as small as possible and written in a disciplined subset of C.
3. **Explicit authority and contracts** — No operation that can affect another domain or the host is permitted without an explicit, logged authorization decision.
4. **Least privilege by default** — Every system receives only the exact capabilities required for its declared purpose.
5. **Narrow terminal interface** — The only way in or out from the host terminal is through a small, carefully reviewed `l2` CLI/TUI and protocol. The client itself holds no raw authority.
6. **Evidence and audit** — All boundary crossings and authority grants are recorded in a form that supports later forensic analysis.

## Memory Safety in C

C is the implementation language for the substrate core. We treat memory safety as a first-class engineering problem:

- Strict coding rules (bounds-checked data structures, no unchecked pointer arithmetic in security-critical paths, explicit ownership).
- Mandatory static analysis on every change that touches the containment boundary or capability handling.
- Avoidance of undefined behavior; use of seL4's own verified runtime components where possible.
- Long-term hardware acceleration path: CHERI (or equivalent) to make spatial memory safety a hardware-enforced property for C code.

We do not claim memory safety equivalent to a memory-safe language in the initial implementation. The combination of seL4 isolation + rigorous process + future CHERI is the strategy.

## Alignment with NSA, CISA, and FBI Standards

l2 explicitly targets the security standards and best practices set forth by the NSA, CISA, and FBI through the following alignments (updated to strengthen compliance):

- **CISA Secure by Design and Secure by Default**: We follow the [CISA Secure by Design principles](https://www.cisa.gov/securebydesign) and the joint [Principles and Approaches for Security-by-Design and -Default](https://www.cisa.gov/sites/default/files/2023-04/principles_approaches_for_security-by-design-default_508_0.pdf) (CISA/NSA/FBI + international partners). This includes prioritizing memory safety, eliminating entire classes of vulnerabilities where possible, and building security into the architecture from the outset.
- **NSA Guidance**: Alignment with NSA recommendations on memory safety (e.g., preference for memory-safe languages or disciplined use of C with guards), network/substrate hardening (least privilege, minimal attack surface), and high-assurance system design. The prototype uses Linux namespaces with explicit authority to reduce attack surface.
- **CISA Cybersecurity Performance Goals (CPGs) and Best Practices**: Incorporation of key CPGs such as asset inventory (systems managed explicitly), vulnerability management (static analysis mandatory), and network segmentation principles adapted to intra-system isolation.
- **Joint CISA/NSA/FBI Advisories**: Avoidance of common misconfigurations (e.g., no ambient authority, explicit contracts only) as highlighted in joint guidance on top 10 misconfigurations and product security bad practices.
- **Prototype Hardening (Linux Namespaces Phase)**: Current isolation via `unshare`/`namespaces` is hardened per CISA/NSA container and host security guidance: full capability dropping, seccomp filters (planned/enhanced), strict policy enforcement for 'strict' mode (no unnecessary privileges, read-only where possible), and rejection of unsafe names/inputs. Future transition to seL4 will exceed current Linux-based controls.

These alignments ensure l2 not only meets but aims to exceed baseline expectations in the referenced standards. No formal certification is claimed yet, but the design supports auditable compliance.

## Cryptography and Host Hardening (v0.4.0)

v0.4.0 delivers the core operational path for high-assurance agentic/AI/MCP systems on the l2 substrate: explicit policy protocols (with `strict-mcp` as the flagship), selectable verified crypto for true system encryption, concrete host hardening, and a closed data-driven loop from trace collection to runtime enforcement. All long guidance uses the same paced "typewriter" output introduced for `l2 sel4-setup` (readable step-by-step; `--fast` / `L2_FAST=1` disables for scripts, CI, or ancient hardware).

These additions do **not** introduce new attack surfaces. The tools are advisory by design (non-destructive defaults, explicit `--apply` or user-pasted commands, confirmations), all operations remain under explicit terminal authority, and runtime enforcement (kill-process default, pre-BPF NEVER_ALLOWED blacklist, Landlock, caps, ns, size-limited profiles) is unchanged or tightened. Everything is audited.

Full details below. See also the collapsible **[Crypto & Hardening](README.md#crypto--hardening-v040)** section in [README.md](README.md) for a high-level overview.

### `l2 crypto` — Only Verified, Most Effective Open-Source Profiles

Users choose a profile; only battle-tested algorithms with strong standardization/analysis are offered:

- `aes256-xts-argon2id`: AES-256-XTS (NIST-approved LUKS disk encryption standard, FIPS-aligned, extensively analyzed) + Argon2id (PHC winner, memory-hard KDF resistant to GPU/ASIC attacks). Default for performance + standards compliance where AES-NI is available.
- `xchacha20-poly1305-argon2id`: XChaCha20-Poly1305 (IETF RFC 8439 constant-time AEAD, no AES dependency, excellent side-channel resistance and performance on any hardware) + Argon2id. Ideal for heterogeneous or older CPUs.
- `hybrid-aes-chacha`: Defense-in-depth mixture. Applies complementary designs to different subsets (e.g., AES-256-XTS for bulk data volumes, XChaCha20-Poly1305 for keys/metadata). Example layered construction printed by the tool: outer LUKS/XChaCha + inner AES-XTS, or dual gocryptfs layers. Reduces risk from any single primitive or implementation.

**Proficient, simple application to the entire system (or l2 state)**:

- Per-directory: gocryptfs (user-space, no root for many cases) with the profile's cipher.
- Volumes/partitions: exact `cryptsetup luksFormat` / `luksOpen` commands with `--cipher`, `--key-size 512`, `--pbkdf argon2id` and tuned iteration/memory parameters (printed for user to review/paste/run).
- Hybrid mode explicitly documents the layered approach.
- `--apply` flow: paced typewriter output of steps, safe non-destructive default, user confirmation, setup of `~/.l2` (or `$L2_DATA_DIR`) encryption guidance, generation of hardened systemd unit template, and report.
- `--network-isolation`: also emits nftables drop rules for the agent user (pairs with harden).
- `--generate-seccomp <trace.log>`: emits a minimal `SystemCallFilter=` stanza + raw list derived from real traces.
- After setup, access only via `l2 exec --policy strict-mcp ...` (or the generated unit) so keys and plaintext are protected by the full substrate (isolation + enforcing filter + audit).

The result is true system encryption that leverages the l2 substrate for key custody and operation isolation — simple and proficient for users while using only proven primitives.

Paced output (type_line / reveal_lines helpers, active on TTY unless L2_FAST) lets users follow along exactly as with sel4-setup and harden.

### `l2 harden` — NSA/CISA/FBI-Aligned Concrete Host & Container Hardening

Prepares the runtime so that `strict-mcp` + crypto deliver on their guarantees. Companion to crypto; use `--profile strict-mcp` to get tuned output.

**Concrete steps emitted (RHEL/Fedora focus, adaptable)**:

- Dedicated low-privilege user (`useradd l2-agent` etc.).
- Kernel hardening sysctls (e.g. `kernel.yama.ptrace_scope=2`, protected symlinks/hardlinks, etc.) written to `/etc/sysctl.d/`.
- Audit rules for tool execution and sensitive syscalls.
- Capability dropping, advanced namespace restrictions (`RestrictNamespaces=~user:pid:net:uts:ipc:`, `PrivateNetwork=`, `ProtectSystem=strict`, `ProtectHome=`, `NoNewPrivileges=true`, `CapabilityBoundingSet=` empty or minimal, `MemoryMax`, etc.).
- `--network-isolation`: nftables-based default-deny outbound for the agent user (cat'ed for review/apply).
- `--generate-seccomp <trace.log>`: parses the log, emits ready-to-use `SystemCallFilter=` block for systemd (plus raw syscall list). Integrates directly with the Phase 1 enforcing filter in the runtime (via `L2_SECCOMP_PROFILE` env or `--profile` to load).

**Automatic artifacts**:

- Rich advisory report written to `~/.l2/harden-reports/` (timestamped, includes commands, rationale, next-steps).
- Full hardened systemd unit template (print + file) with comments tying it to the chosen profile/strict-mcp/trace. Includes all the Protect*/Restrict*/SystemCallFilter/etc. plus a note: "Recommended next: l2 trace ... ; l2 exec --policy strict-mcp ...".
- Paced typewriter output for every long guidance section so the operator can read along.

The script is deliberately advisory (prints what to run, never auto-mutates privileged host state without explicit user action). This matches the "only explicit terminal authority" principle and avoids creating new surfaces.

### Explicit Policy Protocols and `strict-mcp` (Main Focus)

`l2 policies` and `l2 policy <name>` let users discover and inspect guarantees.

- `strict`: Strong baseline isolation (Landlock filesystem restrictions, `no_new_privs`, seccomp).
- `strict-mcp`: The current flagship for agentic/MCP/tool-using workloads. Diverges by being stricter:
  - Phase 1 seccomp enforcing filter is enabled by default (no separate `--enforce` needed in many flows).
  - Tighter Landlock posture (more conservative handling of ambient paths and tool-invocation surfaces).
  - Auto-wires enforcing + policy metadata so users are explicitly aware.
  - Designed to pair directly with `l2 harden --profile strict-mcp` output and `l2 crypto` keys.

Usage is explicit everywhere:

```bash
l2 create my-agent --policy strict-mcp
l2 exec --policy strict-mcp my-agent ./task
l2 trace --policy strict-mcp ./mcp-tool --enforce
```

The `normalize_policy` path and audit logs record the chosen protocol. `strict-mcp` is recommended (and often defaulted) for anything that may invoke external tools or MCP servers.

### Trace Collection → Profile Generation → Enforcing (`l2 trace`)

Closes the data-driven loop required for minimal, workload-specific policies (Phase 1):

```bash
l2 trace --policy strict-mcp ./workload --analyze trace.log
# (or with --enforce for live testing of the filter)
```

- Forces the chosen policy protocol (observer by default; enforcing when requested or via strict-mcp).
- `--analyze` parses logs for unique syscalls + friendly names, produces minimal allowlist.
- The resulting profile is consumable by `l2 harden --generate-seccomp`, `l2 crypto --generate-seccomp`, the runtime enforcing filter (`try_install_seccomp_enforcing_filter`), and systemd units.
- NEVER_ALLOWED blacklist is enforced before any profile is loaded (ptrace, process_vm_*, init_module, kexec_*, reboot, etc. → hard SECURITY VIOLATION + exit).
- Max profile size guard; arch checks; default action `SECCOMP_RET_KILL_PROCESS`.

This is the practical realization of "collect traces, curate allowlist, wire enforcing".

### Integration with the l2 Substrate (No New Attack Surfaces)

- Crypto keys + decrypted state for l2 itself (`~/.l2`) and workloads are only reachable inside strict-mcp (or stricter) contexts.
- Harden prepares the host kernel/audit/user/namespace/seccomp baseline that the substrate then builds upon.
- Generated units reference `l2 exec --policy strict-mcp` (or the equivalent) and load any trace-derived `SystemCallFilter`.
- Runtime sandbox (`apply_strict_sandbox`, `try_install_seccomp_enforcing_filter`) honors the policy protocol, the optional profile file, and the blacklist — all before any workload code runs.
- Additional MCP hardening implemented: full capability bounding set drop (PR_CAPBSET_DROP for all 64) on strict-family, strict-mcp denies all ambient /tmp access (workspace-only for temps/persistence), seccomp profiles auto-discovered from ~/.l2/seccomp/ etc. for strict-mcp without extra env vars.
- Every policy choice, boundary crossing, crypto apply step, and harden recommendation is logged in the tamper-evident audit trail.
- Paced tools, `--fast` escape hatch, explicit confirmations, and dry-run/advisory modes keep the experience usable on real (including old/low-RAM) hardware without compromising the model.

The net result is a practical, verifiable high-assurance path: explicit protocols → substrate isolation → host hardening → verified crypto → data-driven minimal seccomp → full audit, all while preserving the narrow terminal interface and "no ambient authority" core properties. These features directly operationalize CISA Secure by Design/Default, NSA hardening guidance, and joint CISA/NSA/FBI recommendations for least-privilege, supply-chain-aware, auditable agentic systems.

See `CHANGELOG.md`, the scripts (`scripts/crypto.sh`, `scripts/harden.sh`), `src/main.rs` (Crypto/Harden/Trace subcommands + normalize_policy), and `src/sandbox.rs` (enforcing filter + strict-mcp Landlock divergence) for implementation specifics. All v0.4.0 work stays within the original threat model and design principles.

## Reporting Security Issues

Vulnerabilities that affect the containment boundary or allow escape between systems or to the host are treated as critical. See the repository security policy or contact the maintainers.