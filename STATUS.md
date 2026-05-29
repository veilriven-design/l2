# l2 Status

**Current phase**: Skeleton and architectural definition + initial code skeleton.

## Recent Work

- Project repository initialized under veilriven-design/l2
- Tight README and SECURITY.md established
- `docs/TREASURE_CHEST_MODEL.md` added — clarified dynamic "treasure chest" / system abstraction
- `docs/CONTAINMENT_VECTOR_INTERFACE.md` and `docs/MEMORY_SAFETY.md` added
- `src/core/sys.h` added — the complete minimal surface using `l2_sys_*` naming (l2_sys_create, l2_sys_put, l2_sys_exec, etc.)

## Code Skeleton Direction

The skeleton is now oriented around the dynamic Treasure Chest (System) model:

- Systems (chests) are created and destroyed on demand from the host terminal.
- The only possible interactions with any system are the operations declared in `sys.h` using the `l2_sys_*` prefix.
- The substrate enforces strict containment: actions inside a system have no effect outside unless explicitly mediated by the listed operations.

Current files:
- `src/common/safe.{h,c}` — mandatory memory safety guards
- `src/core/sys.h` — the absolute minimal developer surface (l2_sys_* functions)
- `src/core/core.*` — early core that will implement system lifecycle and boundary enforcement

## Near Term Focus

- Implement a minimal in-memory or host-primitive-backed version of the l2_sys_* operations (create/put/get/destroy) that strictly respects the boundary.
- Define the host terminal CLI surface that maps to the functions in sys.h.
- Ensure every crossing of the system boundary is explicit and auditable.
- Keep the TCB for system management as small as possible.

## Principles for All Work

- Every added line of code or documentation must justify itself against the mission of minimal high-assurance MCP and developer computation.
- The system boundary and any code that manages authority are held to the highest review standards.
- Absolute minimal surface: if it's not one of the l2_sys_* operations, it should not be possible.
