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

The external interface and mental model must remain the same whether the backend is the host prototype or seL4.

## Core Documents (the real specification)

- [docs/SYSTEM_MODEL.md](docs/SYSTEM_MODEL.md) — The fundamental model (lifecycle, isolation guarantees, authority)
- [docs/PROTOCOL.md](docs/PROTOCOL.md) — The narrow L2P wire protocol (v1)
- [docs/TERMINAL_INTERFACE.md](docs/TERMINAL_INTERFACE.md) — The terminal experience north star
- [docs/PROTOTYPE_HARDENING_AND_SEL4_PLAN.md](docs/PROTOTYPE_HARDENING_AND_SEL4_PLAN.md) — Hardening phases on Linux + seL4 vision
- [docs/SEL4_INTEGRATION.md](docs/SEL4_INTEGRATION.md) — How the seL4 backend must preserve the narrow interface
- [STATUS.md](STATUS.md) — Living snapshot of what is actually done and current focus areas
- [SECURITY.md](SECURITY.md) — Security requirements and philosophy

## Current State (as of v0.3.2)

See [STATUS.md](STATUS.md) for the authoritative "Done" and "Current Focus" lists.

Highlights:
- Full command surface with real persistence and `--policy strict`
- Landlock + no_new_privs baseline (v0.2.0)
- seccomp observer (Phase 0) — `L2_STRICT_SECCOMP_OBSERVE=1` produces real kernel audit traces
- Append-only authority audit log + `l2 audit` subcommand
- Basic out-of-process `l2-core` binary speaking L2P over stdio (architecture prep)
- Excellent `l2 sel4-setup` on-ramp (Microkit SDK primary path + strong RHEL/Podman guidance)

## Prioritized Work

### Now (Highest Leverage)

1. **seccomp Phase 1 + strict-mcp Policy Protocol (current main focus)**
   - `l2 trace --policy strict-mcp` is the primary data collection tool (observer + enforcing by default).
   - `l2 harden` (new major command) prepares host/container environments according to NSA/CISA/FBI guidance for the agentic/AI/MCP era.
   - `strict-mcp` is the flagship policy protocol that combines strong isolation with the output of `l2 harden`.
   - Continue maturing per-protocol allowlists, analyzer tooling, and user-facing awareness of policy protocols.

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