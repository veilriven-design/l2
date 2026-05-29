# l2 Status

**Current phase**: Skeleton and architectural definition + initial code skeleton.

## Recent Work

- Project repository initialized under veilriven-design/l2
- Tight README and SECURITY.md established
- `docs/TREASURE_CHEST_MODEL.md` added — clarified dynamic "treasure chest" abstraction
- `docs/CONTAINMENT_VECTOR_INTERFACE.md` and `docs/MEMORY_SAFETY.md` added
- `src/core/chest_ops.h` added — the complete minimal surface for all chest operations (create, put, get, exec, destroy, etc.)

## Code Skeleton Direction

The skeleton is now oriented around the dynamic Treasure Chest model:

- Chests are created and destroyed on demand from the host terminal.
- The only possible interactions with any chest are the operations declared in `chest_ops.h`.
- The substrate enforces strict containment: actions inside a chest have no effect outside unless explicitly mediated by the listed operations.
- Early code focuses on the host-integrated substrate rather than a full booted seL4 guest.

Current files:
- `src/common/safe.{h,c}` — mandatory memory safety guards
- `src/core/chest_ops.h` — the absolute minimal developer surface
- `src/core/core.*` — early core that will implement chest lifecycle and boundary enforcement

The previous Microkit boot-oriented files remain as reference for strong-isolation backends but are no longer the primary path for the initial skeleton.

## Near Term Focus

- Implement a minimal in-memory or host-primitive-backed version of the chest operations (create/put/get/destroy) that strictly respects the boundary.
- Define the host terminal CLI surface that maps to `chest_ops.h`.
- Ensure every crossing of the chest boundary is explicit and auditable.
- Keep the TCB for chest management as small as possible.

## Principles for All Work

- Every added line of code or documentation must justify itself against the mission of minimal high-assurance MCP and developer computation.
- The chest boundary and any code that manages authority are held to the highest review standards.
- Absolute minimal surface: if it's not one of the operations in chest_ops.h, it should not be possible.
