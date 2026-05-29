# l2 Status

**Current phase**: Skeleton and architectural definition + initial code skeleton.

## Recent Work

- Project repository initialized under veilriven-design/l2
- Tight README and SECURITY.md established
- Core concepts documented (Containment Vector, Host Terminal Interface, etc.)
- `docs/CONTAINMENT_VECTOR_INTERFACE.md` and `docs/MEMORY_SAFETY.md` added

## Code Skeleton (Just Started)

Initial source tree under `src/`:

- `src/README.md` — philosophy and structure
- `src/common/safe.{h,c}` — foundational memory safety guards (l2_bounds_check, l2_memcpy_safe, l2_zero, etc.)
- `src/core/core.{h,c}` — minimal l2 core Protection Domain (will become the authority root)
- `src/vector/example_vector.c` — demonstration of code running inside a containment vector
- `l2.system` — initial Microkit system description

All new C code is written from day one under the rules defined in `docs/MEMORY_SAFETY.md`.

## Near Term (First Milestone)

- Produce a minimal bootable seL4 + Microkit system under QEMU that:
  - Boots the l2 core
  - Boots the example vector
  - Demonstrates basic separation and debug output
- Expand the core to actually create simple static containment vectors at boot
- Define the first version of the narrow host terminal protocol

## Principles for All Work

- Every added line of code or documentation must justify itself against the mission of minimal high-assurance MCP and developer computation.
- The containment boundary and any code that manages authority are held to the highest review standards.
- We favor proven seL4 ecosystem components (Microkit, sel4runtime, etc.) over new inventions in the early stages.
