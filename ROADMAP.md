# l2 Roadmap

**Minimal high-assurance substrate. Terminal-first. Narrow surface. seL4 as the root of trust.**

This document gives a one-page view of direction and priorities. Detailed design lives in the `docs/` directory.

## Vision (unchanging)

- Dynamic, on-demand isolated execution contexts
- Driven exclusively from the terminal
- Tiny, auditable public surface (`l2` CLI + narrow L2P protocol + `l2_sys_*` C interface)
- Total cleanup on destroy
- Extreme restraint on scope and code
- Long-term backend: seL4 / Microkit (verified capability-based isolation)
- Short/medium-term: Best-effort high-quality Linux prototype using Landlock + namespaces + seccomp + no_new_privs
- Full safety "ransom-hardened" policy protocol + ransomware resistance demos for malicious code containment validation (WannaCry-class testing when ready)

The external interface and mental model must remain the same whether the backend is the host prototype or seL4.

## Core Documents (the real specification)

- [docs/SYSTEM_MODEL.md](docs/SYSTEM_MODEL.md) — The fundamental model (lifecycle, isolation guarantees, authority)
- [docs/PROTOCOL.md](docs/PROTOCOL.md) — The narrow L2P wire protocol (v1)
- [docs/TERMINAL_INTERFACE.md](docs/TERMINAL_INTERFACE.md) — The terminal experience north star
- [docs/PROTOTYPE_HARDENING_AND_SEL4_PLAN.md](docs/PROTOTYPE_HARDENING_AND_SEL4_PLAN.md) — Hardening phases on Linux + seL4 vision
- [docs/SEL4_INTEGRATION.md](docs/SEL4_INTEGRATION.md) — How the seL4 backend must preserve the narrow interface
- [STATUS.md](STATUS.md) — Living snapshot of what is actually done and current focus areas
- [SECURITY.md](SECURITY.md) — Security requirements and philosophy

## Current State (as of v0.4.4)

See [STATUS.md](STATUS.md) for the authoritative "Done" and "Current Focus" lists.

Highlights (v0.4.0+ focus on agentic/AI/MCP hardening + full-safety):
- Explicit policy protocols (`strict-mcp` as flagship for agentic/MCP; `ransom-hardened` for full-safety ransomware/malicious testing) + `l2 policies` / `l2 policy <name>` discovery.
- **`l2 crypto`**: Selectable verified profiles (AES-256-XTS-Argon2id, XChaCha20-Poly1305-Argon2id, hybrid) for true system encryption (LUKS + gocryptfs). Hybrid mixes complementary algorithms. Paced typewriter output. Integrated with l2 isolation (keys protected by strict-mcp / ransom-hardened contexts).
- **`l2 harden`**: Concrete NSA/CISA/FBI-aligned host/container hardening (paced output). `--network-isolation`, auto-generated systemd units, capability dropping, advanced namespaces, trace-driven seccomp profiles. Supports `strict-mcp` and `ransom-hardened` (ransomware-specific).
- **`l2 trace`** with policy support + `--analyze` → real minimal profiles that the runtime enforcing filter loads directly (exercised by ransom-hardened too).
- Full integration: policies + crypto + host prep + trace data + `l2 audit --test` (harden json consumption) form a coherent high-assurance path. Includes ransomware containment validation path.
- Paced "typewriter" output in `l2 sel4-setup`, `l2 harden`, `l2 crypto` for readable long guidance (`--fast` to disable).
- Excellent `l2 sel4-setup` on-ramp (Microkit SDK primary path + strong RHEL/Podman guidance).
- Landlock + no_new_privs + seccomp baseline (Phase 0 observer complete; Phase 1 enforcing active for strict-family policies including ransom-hardened).
- Append-only authority audit log + `l2 audit` subcommand (incl. ransomware check).
- Basic out-of-process `l2-core` binary speaking L2P over stdio (architecture prep).
- `docs/examples/l2_ransomware_resistance_demo.c` + dedicated `ransom-hardened` protocol + harden/audit for repeatable containment testing.

## Prioritized Work

### Now (Highest Leverage)

1. **Agentic/AI/MCP hardening track (v0.4.0+ main focus)**
   - `l2 crypto` + `strict-mcp` + `ransom-hardened` + `l2 harden` + `l2 audit --test` as a complete operational path (incl. ransomware containment validation).
   - Continue maturing: more aggressive defaults in crypto/harden, per-protocol divergence (e.g. network denial, tool-specific rules in strict-mcp; full safety in ransom-hardened), expanded automated application in `l2 harden` (more distros, direct profile application).
   - `l2 trace --policy strict-mcp` (and ransom-hardened for sims) remains the primary data collection tool (observer + enforcing by default); feed into `l2 harden --generate-seccomp`.
   - `l2 harden --profile strict-mcp` (or `ransom-hardened`) prepares hosts/containers per NSA/CISA/FBI guidance (and ransomware-specific) for the agentic era.
   - `strict-mcp` is the flagship policy protocol for normal use (stronger defaults than `strict`, integrates crypto profiles and host hardening); `ransom-hardened` for explicit malicious code testing.
   - Mature per-protocol allowlists, analyzer tooling (`l2 trace --analyze`), user-facing awareness (`l2 policies`), and integration (e.g. auto-wiring generated seccomp profiles into runtime, harden json to audit).
   - `docs/examples/l2_ransomware_resistance_demo.c` as canonical sim for proving `ransom-hardened` controls.

2. **Deeper crypto + host hardening operationalization**
   - Make generated profiles/units from `l2 crypto`/`l2 harden` directly consumable with one command.
   - Expand concrete steps (more distros, TPM integration, fscrypt, etc.).
   - Policy-aware differences in the runtime (Landlock, seccomp, namespaces) for `strict-mcp` vs. `strict`.

2. **Mature the L2P / core split**
   - Expand the operations implemented over the wire in `host/core.rs`.
   - Make the main `l2` CLI able to drive a real out-of-process `l2-core` for normal development (validates the protocol).
   - This is prerequisite infrastructure for any serious seL4 port.

### Next

- Capability dropping and tighter bounding sets (continuing the hardening plan).
- More isolation-focused tests and property checking.
- Improved observability / tracing commands (building on the audit log and seccomp work).
- Clean up stale sections in planning documents (some older seL4 Docker ideas are superseded by the current `l2 sel4-setup` + Microkit SDK approach).

### Longer Term (seL4 Track)

- Actual implementation of the narrow core as a Microkit protection domain.
- l2 systems expressed as Microkit `.system` descriptions.
- Use of the verified seL4 kernel + capability model as the real root of trust.

## Non-Goals / Out of Scope

- Effect systems, lattices, rich type systems
- Packaging / distribution beyond the narrow binary + sel4-setup on-ramp
- Graphical interfaces or heavy interactive TUIs (light REPL-style helpers are acceptable if they stay tiny)
- Scope creep of any kind

Keep it small. Keep it terminal. Keep it high-assurance.

## How to Contribute / Work on l2

The project moves deliberately. Before proposing or implementing something new:

1. Check that it fits the model in `docs/SYSTEM_MODEL.md` and the narrow protocol.
2. Check it advances one of the priorities above (especially hardening Phase 1 or the core split).
3. Prefer small, reviewable changes that can be landed cleanly.

Current high-signal starting points:
- Trace collection and allowlist work for seccomp Phase 1
- Filling out more L2P operations in `host/core.rs` and wiring the client to use the external core

---

*This roadmap is intentionally short. The detailed constraints and design decisions live in the documents linked above.*