# Status

**v0.4.0 released** — Major milestone on the agentic/AI/MCP hardening track, including new `l2 crypto` feature for selecting and applying verified crypto profiles (AES-256-XTS-Argon2id, XChaCha20-Poly1305-Argon2id, hybrid) system-wide via LUKS/gocryptfs integrated with l2 isolation (strict-mcp). Includes aggressive defaults, network isolation flag, auto-generated systemd units and seccomp profiles from traces, capability dropping, advanced namespaces in harden script. `l2 crypto` uses paced typewriter output. v0.3.9 and earlier tags preserved.
- New `l2 harden` command + `scripts/harden.sh` (modeled after sel4-setup with paced typewriter output). Applies NSA/CISA/FBI-aligned concrete hardening steps for the agentic era.
- `strict-mcp` policy protocol is now the main focus: diverges from `strict` with aggressive defaults (enforcing seccomp on by default, tighter posture).
- Full integration: `l2 trace --policy strict-mcp` + `--analyze`, `l2 harden --generate-seccomp`, and the runtime enforcing filter can directly load generated minimal profiles.
- Automatic generation of hardened systemd unit templates from `l2 harden`.
- New commands: `l2 policies` and `l2 policy <name>` (especially `l2 policy strict-mcp`).
- Significant maturity in seccomp tooling, capability/namespace guidance, and network isolation options.
- `l2 harden --network-isolation` and concrete host hardening steps (sysctls, dedicated users, audit rules, etc.).

This release makes `strict-mcp` + `l2 harden` a real, operational high-assurance path for MCP/agentic workloads. v0.3.2 and earlier tags preserved.

## Charter

l2 is the minimal high-assurance Latticra substrate:
- Dynamic, on-demand isolated execution contexts
- Driven exclusively from the terminal (CLI primary interface)
- Tiny public surface
- Total cleanup on destroy
- Extreme restraint on scope and code

## Done (Current Prototype)

- Refocus + narrow docs (TERMINAL_INTERFACE, PROTOCOL, etc.)
- Working Rust CLI with **full command surface** (create/put/get/exec/list/destroy/status/revoke + `--json`)
- **Real persistence**: systems + objects survive across separate `l2` invocations (stored in `~/.l2/state.json`)
- Real Linux namespace isolation for `exec` (`unshare`)
- **Real Landlock + no_new_privs sandboxing for `--policy strict`**: workspace-confined writes, RO+EXEC on system essentials (v0.2.0)
- **Full `l2 sel4-setup` command**: one-command seL4/Microkit bootstrap with:
  - Official Microkit SDK 2.2.0 tarball download (clear primary/fast path)
  - Distro-aware behavior (especially strong support for RHEL/Fedora + podman)
  - Automatic pre-pull of base images using `docker.io/trustworthysystems/...` fully-qualified names (bakes in the fix for Podman's "short-name resolution enforced but cannot prompt without a TTY" error on RHEL)
  - On RHEL+podman: heavy time/hardware warnings (hours to 40h+ on ancient/low-RAM machines); SDK + host cross tools presented as the default; full container requires typing an explicit confirmation phrase (v0.3.1 UX hardening for old hardware like X200-class systems)
  - High-quality generated `README-l2-sel4.md` with the RHEL/Podman one-time fix permanently documented and strong guidance on choosing the right path by hardware capability
- Dramatically improved `list` output and overall UX
- `demo.sh` removed (commands documented directly in README instead)

## Current Focus

1. Better host isolation (seccomp-bpf, capability dropping, tighter Landlock policies, user+mount ns) — Landlock baseline v0.2.0. Phase 0 complete: real `SECCOMP_RET_LOG` + `FLAG_LOG` observer now works (`L2_STRICT_SECCOMP_OBSERVE=1`). Kernel audit logs for strict workloads are available. See `src/sandbox.rs` + docs/PROTOTYPE_HARDENING_AND_SEL4_PLAN.md for usage. Ready for trace collection → Phase 1 enforcing filter.

2. Audit logging: Basic append-only JSONL authority audit log (`audit.log` in data dir) now implemented for create/put/exec/destroy/revoke/escalate/sandbox (and oneshot temp systems). Includes `l2 audit` subcommand. Respects SUDO_USER. See `src/audit.rs`. This directly addresses the "Evidence and audit" requirement in SECURITY.md.

3. Correctness gaps: Deeper work — non-panicking JSON output paths, load_state now warns on corrupt JSON, many silent cleanups now use warn_on_cleanup_err, 17 tests (strong coverage on data_dir, state roundtrips, error paths, isolation helpers). See recent changes in src/main.rs.

4. Architecture prep for core split: l2-core binary now implements basic L2P handler (ping/status over stdio). See host/core.rs. Clear boundary (trait + out-of-process) and C core work next. The main `l2` prototype remains the daily driver.

5. seL4/Microkit backend (parallel track) — `l2 sel4-setup` is the current on-ramp. Out-of-process `l2-core` speaking the real L2P protocol and disciplined C implementation remain active focus.

## How to Use Right Now

See [ROADMAP.md](ROADMAP.md) for the current prioritized direction.

See the full install + usage instructions in `README.md` (covers both `cargo build --release` and `cargo install --path . --force`).

Quick reference:
```bash
cargo build --release          # or cargo install --path . --force
l2 create demo --policy strict
l2 put demo note.txt --content 'hello'
l2 exec demo 'cat note.txt'
l2 destroy demo
l2 sel4-setup
```

Override state with `L2_DATA_DIR=/path l2 ...`.

## Out of Scope
Effect systems, lattices, packaging, physics work, scope creep.

Keep it small. Keep it terminal. Keep it high-assurance.
