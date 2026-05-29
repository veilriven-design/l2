# l2

**l2** is a minimal high-assurance system substrate anchored on the seL4 microkernel.

It supplies a **containment vector** — a strongly isolated execution environment — in which MCP servers and general developer computations run under explicit authority, auditable effects, and the formal guarantees of seL4.

Developers interact with l2 through a narrow, high-assurance interface exposed via the ordinary terminal on the host operating system. The substrate itself runs inside seL4 (typically in a locked-down virtual machine on the host).

## Mission

Provide the smallest practical substrate that lets developers safely manage and execute MCP workloads and other sensitive computation on machines they already use, while meeting the spirit of modern high-assurance guidance.

## Core Properties

- seL4 as the verified kernel foundation
- Minimal trusted computing base in userland (C + Microkit-style protection domains)
- Rigorous memory safety discipline and guards in C
- Capability-based containment and authority management
- Explicit contracts and effect discipline for all operations that cross containment boundaries
- Terminal-first interface usable from any host OS

## Non-Goals (Current Scope)

- Replacing a general-purpose host OS
- Large language runtimes or rich application frameworks inside the TCB
- Broad device driver support or full POSIX surface

## Status

Early skeleton. See `STATUS.md` and `docs/` for current direction.

## Getting Started

This repository currently contains the project skeleton and architectural definitions. The first concrete implementation milestone will target a reproducible seL4 + Microkit environment running under QEMU with a basic host terminal shim.

## Contributing

See `CONTRIBUTING.md` (to be added) and `SECURITY.md`.

High-assurance work demands precision. Changes that affect the containment boundary, authority model, or any code that could run with elevated rights receive extra scrutiny.

## License

To be determined. Likely a permissive license compatible with the seL4 ecosystem (BSD-2-Clause or similar).
