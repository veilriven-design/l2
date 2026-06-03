# System Model

An l2 system is a dynamic, isolated execution context created and destroyed on demand from the terminal.

## Lifecycle (all explicit)

1. `l2 create --policy <name>` — The core allocates the context and grants initial capabilities according to the chosen protocol (e.g. `strict-mcp` for agentic, `ransom-hardened` for full-safety malicious testing, great-harden for supreme with net:none + tiny fs, `na` for network-audit/pentest, `tomato` for router network config complementing na). Grants are unforgeable capability tokens (modeled on seL4 caps, Capsicum fd-rights from FreeBSD, CHERI hardware permissions, Genode delegation). v0.5.8: `tomato` + `na` integrated (masked wan0/lan0 or na0 surfaces for contained router config + audit/pentest; fully disposable). RAT defense etc from prior. All contained to explicit ws only.
2. `l2 put` — Operator places code, data, or credentials into the system (mediated, logged). May extend grants.
3. `l2 exec` — Run work inside the system using only the capabilities it currently holds (enforced by sandbox: Landlock=unveil, seccomp=pledge, no ambient).
4. `l2 get` — Retrieve results or artifacts (again, explicit and mediated).
5. `l2 destroy` — The core tears down the system. Destruction must be total: no residual capabilities, memory, or observable state remain that could affect the host or other systems. (Revoke all caps.)

## Isolation Guarantees

- Nothing inside a system can directly affect the host or any other system except through the narrow, core-mediated surface.
- All authority originates from the core (no ambient, like seL4/Capsicum/CHERI/Genode/OpenBSD pledge).
- Revocation is effective and timely (remove from grant list; no way to retain).
- Systems cannot communicate with each other unless explicitly authorized by the core (and even then, only through mediated channels). Grants have explicit rights (fs:*, net:*, exec, audit:log etc).

## Backend Reality

- Long-term target: seL4 (or equivalent verified kernel) for strong spatial/temporal isolation and capability-based authority (PDs + caps delegation + IPC).
- Short-term / development: Best available host isolation primitives (namespaces, seccomp=pledge equiv, Landlock=unveil equiv, virtualization, etc.) with honest documentation of their limits. Emulates Capsicum rights, CHERI bounds where possible in software (safe.h, Landlock).
- The external interface (`l2` commands and `l2_sys_*`) remains the same regardless of backend. L2P carries capability intent.

## Core Invariant

The trusted computing base that can create, manage, or destroy systems must be minimized at every layer. The terminal operator is the only source of new authority.

This model learns from open-source high-assurance systems:
- seL4: verified cap-based kernel, PDs, revoke, narrow interface.
- Capsicum (FreeBSD): fine-grained rights on resources (e.g. fd caps: read/write/exec/no-fork).
- CHERI: hardware capabilities for memory safety + perms (bounds, no forge); software emulation in l2 safe layer + Landlock.
- Genode: recursive cap delegation, microkernel components with least-priv.
- OpenBSD: pledge(2)/unveil(2) "secure by default" + reduce attack surface immediately (mapped to seccomp+Landlock in l2, applied early in CLI + payloads).

This is the entire model. Everything else is implementation detail or out of scope.
