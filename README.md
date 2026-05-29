# l2

**l2** is a minimal high-assurance system substrate anchored on the seL4 microkernel.

It supplies a **containment vector** — presented to the developer as a **Treasure Chest** — a strongly isolated environment on the host system in which you can put things, make things happen, and pull results out, with the guarantee that nothing inside can affect anything outside except through narrow, explicit, auditable operations.

Developers interact with chests through the ordinary terminal. The substrate enforces the boundary using the strongest available mechanisms (seL4 where possible, combined with minimal host primitives).

## Mission

Provide the smallest practical substrate that lets developers safely manage and execute MCP workloads and other sensitive computation using dynamic, on-demand treasure chests.

## Core Properties

- Dynamic chests (created and destroyed on demand, no always-on background system)
- Absolute minimal surface: only the operations declared in `src/core/chest_ops.h`
- Rigorous memory safety discipline and guards in C
- Capability-based containment and authority management
- Explicit contracts and effect discipline for all boundary crossings
- Terminal-first interface usable from any host OS

## Non-Goals (Current Scope)

- Replacing a general-purpose host OS
- Large language runtimes or rich application frameworks inside the TCB
- Broad device driver support or full POSIX surface
- Persistent always-running virtual machines

## Status

Early skeleton. The Treasure Chest model and minimal operation surface (`chest_ops.h`) are now the center of the design. See `STATUS.md`, `docs/TREASURE_CHEST_MODEL.md`, and `src/` for current direction.

## Getting Started

The repository contains architecture, security rules, and the initial code skeleton for the treasure chest abstraction.

## Contributing

See `CONTRIBUTING.md` and `SECURITY.md`.

High-assurance work demands precision. Changes that affect the chest boundary or authority model receive extra scrutiny.

## License

BSD-2-Clause (see LICENSE).
