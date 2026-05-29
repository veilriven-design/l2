# l2

**l2** is a minimal high-assurance system substrate anchored on the seL4 microkernel.

It provides dynamic, isolated execution contexts (l2 Systems) on a host system. Each l2 System is a strongly contained environment in which code and data can be placed and executed, with the guarantee that effects are confined to that system unless explicitly mediated through the narrow interface defined in src/core/sys.h.

The substrate is operated through the host terminal. l2 Systems are created and destroyed on demand.

## Mission

Provide the smallest practical substrate for high-assurance, dynamic, isolated computation (including MCP workloads) on developer host systems.

## Core Properties

- Dynamic l2 Systems with on-demand creation and destruction
- Absolute minimal interface: only the l2_sys_* operations in src/core/sys.h
- Rigorous memory safety discipline and guards in C
- Explicit authority and effect control
- Terminal-driven operation on any host that can run a terminal

## Non-Goals (Current Scope)

- General-purpose host OS replacement
- Rich language runtimes or application frameworks in the TCB
- Broad device support or POSIX compatibility layer
- Long-lived persistent virtual machines

## Status

Early skeleton. The l2 System model and minimal interface (sys.h) are the focus. See STATUS.md, docs/SYSTEM_MODEL.md, docs/CONTAINMENT_VECTOR_INTERFACE.md, and src/.

## Getting Started

The repository contains the architectural definitions and initial code skeleton for the l2 substrate.

## Contributing

See CONTRIBUTING.md and SECURITY.md.

## License

BSD-2-Clause (see LICENSE).
