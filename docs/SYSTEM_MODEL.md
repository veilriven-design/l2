# System Model

An l2 system is a dynamic, isolated execution context created and destroyed on demand from the terminal.

## Lifecycle (all explicit)

1. `l2 create` — The core allocates the context and grants initial capabilities according to policy.
2. `l2 put` — Operator places code, data, or credentials into the system (mediated, logged).
3. `l2 exec` — Run work inside the system using only the capabilities it currently holds.
4. `l2 get` — Retrieve results or artifacts (again, explicit and mediated).
5. `l2 destroy` — The core tears down the system. Destruction must be total: no residual capabilities, memory, or observable state remain that could affect the host or other systems.

## Isolation Guarantees

- Nothing inside a system can directly affect the host or any other system except through the narrow, core-mediated surface.
- All authority originates from the core.
- Revocation is effective and timely.
- Systems cannot communicate with each other unless explicitly authorized by the core (and even then, only through mediated channels).

## Backend Reality

- Long-term target: seL4 (or equivalent verified kernel) for strong spatial/temporal isolation and capability-based authority.
- Short-term / development: Best available host isolation primitives (namespaces, seccomp, virtualization, etc.) with honest documentation of their limits.
- The external interface (`l2` commands and `l2_sys_*`) remains the same regardless of backend.

## Core Invariant

The trusted computing base that can create, manage, or destroy systems must be minimized at every layer. The terminal operator is the only source of new authority.

This is the entire model. Everything else is implementation detail or out of scope.
