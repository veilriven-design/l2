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
- Full safety "ransom-hardened" policy protocol + ransomware resistance demos (WannaCry-class) + supply-chain worm resistance demos (Miasma-style npm credential theft + propagation) for malicious code containment validation (testing when ready)

The external interface and mental model must remain the same whether the backend is the host prototype or seL4.

## Core Documents (the real specification)

- [docs/SYSTEM_MODEL.md](docs/SYSTEM_MODEL.md) — The fundamental model (lifecycle, isolation guarantees, authority)
- [docs/PROTOCOL.md](docs/PROTOCOL.md) — The narrow L2P wire protocol (v1)
- [docs/TERMINAL_INTERFACE.md](docs/TERMINAL_INTERFACE.md) — The terminal experience north star
- [docs/PROTOTYPE_HARDENING_AND_SEL4_PLAN.md](docs/PROTOTYPE_HARDENING_AND_SEL4_PLAN.md) — Hardening phases on Linux + seL4 vision
- [docs/SEL4_INTEGRATION.md](docs/SEL4_INTEGRATION.md) — How the seL4 backend must preserve the narrow interface
- [STATUS.md](STATUS.md) — Living snapshot of what is actually done and current focus areas
- [SECURITY.md](SECURITY.md) — Security requirements and philosophy

## Current State (as of v0.4.8)

See [STATUS.md](STATUS.md) for the authoritative "Done" and "Current Focus" lists.

Highlights (v0.4.0+ focus on agentic/AI/MCP hardening + full-safety):
- Explicit policy protocols (`strict-mcp` as flagship for agentic/MCP; `ransom-hardened` for full-safety ransomware/malicious testing + Miasma supply-chain worm resistance; `great-harden` via `l2 great-harden` for supreme aerospace/industrial impenetrable) + `l2 policies` / `l2 policy <name>` discovery.
- **`l2 crypto`**: Selectable verified profiles (AES-256-XTS-Argon2id, XChaCha20-Poly1305-Argon2id, hybrid) for true system encryption (LUKS + gocryptfs). Hybrid mixes complementary algorithms. Paced typewriter output. Integrated with l2 isolation (keys protected by strict-mcp / ransom-hardened contexts).
- **`l2 harden`**: Concrete NSA/CISA/FBI-aligned host/container hardening (paced output). `--network-isolation`, auto-generated systemd units, capability dropping, advanced namespaces, trace-driven seccomp profiles. Supports `strict-mcp` and `ransom-hardened` (ransomware-specific). **NEW `l2 great-harden`**: supreme aerospace/industrial mode for higher assurance, gap-closing, impenetrable servers (extreme lockdown, great policy).
- **`l2 trace`** with policy support + `--analyze` → real minimal profiles that the runtime enforcing filter loads directly (exercised by ransom-hardened too).
- Full integration: policies + crypto + host prep + trace data + `l2 audit --test` (harden json consumption) form a coherent high-assurance path. Includes ransomware containment validation path.
- Paced "typewriter" output in `l2 sel4-setup`, `l2 harden`, `l2 crypto` for readable long guidance (`--fast` to disable).
- Excellent `l2 sel4-setup` on-ramp (Microkit SDK primary path + strong RHEL/Podman guidance).
- Landlock + no_new_privs + seccomp baseline (Phase 0 observer complete; Phase 1 enforcing active for strict-family policies including ransom-hardened).
- Append-only authority audit log + `l2 audit` subcommand (incl. ransomware check).
- Basic out-of-process `l2-core` binary speaking L2P over stdio (architecture prep).
- `docs/examples/l2_ransomware_resistance_demo.c` + `l2_miasma_resistance_demo.c` + `l2_malware_cancer_resistance_demo.c` + dedicated `ransom-hardened` / `great-harden` protocols + harden/audit for repeatable ransomware + Miasma supply-chain worm + viruses + AIO malware-cancer (direct l2 substrate attack) containment testing — the **grand demonstration of l2 North-Star Containment**. **NEW `l2 great-harden`** + great-harden policy for supreme aerospace/industrial (impenetrable, closes logic gaps, substrate defense, North-Star Containment).

## Prioritized Work

### Now (Highest Leverage)

1. **Agentic/AI/MCP hardening track (v0.4.0+ main focus) + great-harden for aerospace/industrial**
   - `l2 crypto` + `strict-mcp` + `ransom-hardened` + `l2 harden` + `l2 audit --test` + **NEW `l2 great-harden`** as a complete operational path (incl. ransomware containment validation + Miasma supply-chain worm resistance via dedicated demo + AIO malware-cancer + viruses substrate defense sim + supreme higher-assurance for aerospace/industrial - closes logic gaps, achieves l2 North-Star Containment, makes servers impenetrable; the grand demo).
   - Continue maturing: more aggressive defaults in crypto/harden, per-protocol divergence (e.g. network denial, tool-specific rules in strict-mcp; full safety in ransom-hardened; supreme extreme in great-harden), expanded automated application in `l2 harden` (see #7 for direct consumability of artifacts via --apply etc., more distros, direct profile application).
   - `l2 trace --policy strict-mcp` (and ransom-hardened for sims, great-harden for critical) remains the primary data collection tool (observer + enforcing by default); feed into `l2 harden --generate-seccomp`.
   - `l2 harden --profile strict-mcp` (or `ransom-hardened` or `great-harden`) prepares hosts/containers per NSA/CISA/FBI guidance (and ransomware-specific, aerospace supreme) for the agentic era.
   - `strict-mcp` is the flagship policy protocol for normal use (stronger defaults than `strict`, integrates crypto profiles and host hardening); `ransom-hardened` for explicit malicious code testing; `great-harden` (via `l2 great-harden`) for supreme aerospace/industrial impenetrable + AIO substrate defense.
   - Mature per-protocol allowlists, analyzer tooling (`l2 trace --analyze`), user-facing awareness (`l2 policies`), and integration (e.g. auto-wiring generated seccomp profiles into runtime, harden json to audit).
   - `docs/examples/l2_ransomware_resistance_demo.c` + `l2_miasma_resistance_demo.c` + `l2_malware_cancer_resistance_demo.c` as canonical sims for proving `ransom-hardened` / `great-harden` controls against ransomware, Miasma-style supply-chain worms, and direct AIO attacks on the l2 substrate (state/trace/audit/crypto + escape vectors). `l2 great-harden` for critical infra validation.

2. **Deeper crypto + host hardening operationalization** (current highest-leverage next after v0.4.8; tracked in #7)
   - Make generated profiles/units from `l2 crypto`/`l2 harden` directly consumable with one command (add `--apply` to `l2 harden` modeled on crypto; safe/audited application of units, profiles, nft rules, sysctls where possible; update `<profile>-latest.json` with applied evidence).
   - Close the loop so `l2 harden --profile X --apply ; l2 audit --test` is the repeatable end-to-end for standards + real state change.
   - Expand concrete steps (more distros, TPM integration, fscrypt, etc.).
   - Policy-aware differences in the runtime (Landlock, seccomp, namespaces) for `strict-mcp` vs. `strict` (and ransom-hardened).
   - See new GitHub #7 for details + constraints (keep narrow, explicit authority, no new surfaces).

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