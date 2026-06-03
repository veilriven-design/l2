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
- [docs/STATUS.md](STATUS.md) — Living snapshot of what is actually done and current focus areas
- [docs/SECURITY.md](SECURITY.md) — Security requirements and philosophy

## Current State (as of v0.5.0)

See [docs/STATUS.md](STATUS.md) for the authoritative "Done" and "Current Focus" lists.

v0.5.0 qualifiers achieved:
- L2P / core split **mature**: l2::Host (Linux backend impl of L2Core trait) + out-of-proc l2-core (host/core.rs) provide real E2E exercised narrow protocol boundary (create/put/get/destroy/list + exec/revoke intents). L2_USE_CORE=1 drives it; default in-proc for compat. 
- `l2 harden --apply` fully operational (writes + loads real units, profiles, sysctls, audit rules, nft; produces "applied":true + applied_list in *-latest.json for direct automation + `l2 audit --test` consumption; --fast/--json auto no-prompt; matches crypto UX).
- seL4/Microkit E2E progress: C PD skeleton (src/core/core.c) + safe FFI (common/safe) + narrow l2_sys_* (core/host.c) + L2P surface defined and dual to Rust Host. The contract guarantees zero change to external `l2` CLI, policies (great-harden etc), L2_DATA_DIR, North-Star demos, or evidence when swapping backends.
- All prior (PQC/liboqs quantum prep, full-weakness audit, malware-cancer AIO, crypto redteam, great-harden supreme for aerospace, North-Star Containment grand repeatable demos, full NSA/CISA 2026 alignment, "prepare prepare prepare") preserved and integrated.

Highlights (agentic/AI/MCP + full-safety + v0.5 maturity):
- Explicit policy protocols (`strict-mcp`, `ransom-hardened`, `great-harden`) + discovery.
- `l2 crypto` (incl. hybrid-pqc-mlkem via open-source liboqs FIPS 203) + redteam onslaught (10+ NSA-level + quantum harvest vector).
- `l2 harden` + operational `--apply` + `l2 great-harden` for supreme (impenetrable servers).
- `l2 trace` + direct loadable profiles + runtime enforcing.
- Full integration with `l2 audit --test` (10+ checks + North-Star + standards) + resistance demos (`l2_*_resistance_demo.c` + cancer + full-weakness + redteam) for grand evidence loop.
- Landlock + seccomp Phase 1 + caps + ns baseline exercised under policies.
- Audit log + tamper chain.
- Mature out-of-process L2P + C seL4 PD skeleton (narrow surface preserved for swap).
- `l2 sel4-setup` on-ramp (Microkit primary).

## Prioritized Work

### Now (Highest Leverage — v0.5.0 done; sustain the north star + deepen seL4)

1. **Agentic/AI/MCP + aerospace (great-harden) + North-Star Containment (sustain)**
   - Keep the complete operational path (`l2 crypto` PQC + strict-mcp/ransom/great-harden + operational harden --apply + audit --test + the AIO resistance demos) as the beautiful, repeatable grand demonstration. "prepare prepare prepare — run the demo when confident".
   - North-Star Containment evidence (malware-cancer AIO on substrate + crypto redteam 10+ vectors incl quantum + full weakness audit + ransomware/Miasma/virus) must stay green under great-harden + crypto --apply + explicit put/exec + `l2 audit --test`.
   - Continue minor polish on allowlists, distros, and integration; no scope creep.

2. **L2P / core + seL4 (v0.5.0 qualifier achieved; next traction)**
   - L2P v1 E2E exercised on the mature Host + trait + l2-core. Narrow surface (L2P ops + l2_sys_*) is the contract.
   - Next: real PD creation + cap delegation in the seL4 C side, FFI or IPC wiring so a seL4 system can run the same l2 create/put/exec/audit loop and produce identical North-Star evidence. Linux Host remains the daily driver and reference.
   - Invariant: users, CLI, policies, L2_DATA_DIR, demos, and `l2 audit --test` never notice the backend.

3. **Operationalization sustain (harden --apply etc.)**
   - Expand safe automation surface of --apply (more rules, SBOM hooks) while keeping everything explicit + audited. L2_BASE/harden/ artifacts must remain directly usable by CI/automation.

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