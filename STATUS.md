# l2 Status

**Current phase**: Skeleton and architectural definition + initial code skeleton.

## Recent Work

- Project repository initialized under veilriven-design/l2
- Tight README and SECURITY.md established
- docs/SYSTEM_MODEL.md added (technical definition of l2 Systems)
- docs/CONTAINMENT_VECTOR_INTERFACE.md and docs/MEMORY_SAFETY.md added
- src/core/sys.h added (l2_sys_* minimal interface)

## Code Skeleton

The skeleton implements the dynamic l2 System model:

- Systems are created and destroyed on demand.
- All interaction is restricted to the operations in sys.h.
- Strict containment is enforced between systems and the host.

Current key files:
- src/common/safe.{h,c} — memory safety primitives
- src/core/sys.h — public l2_sys_* interface
- src/core/core.* — core implementation

## Near Term

- Minimal implementation of the l2_sys_* operations backed by host primitives.
- Host terminal interface (CLI) that maps directly to sys.h.
- Continued refinement of boundary enforcement and audit requirements.

## Principles

- Every addition must be justified by the requirement for a minimal, high-assurance, dynamic isolated execution substrate.
- The interface in sys.h defines the complete permitted surface.
- TCB for system creation and authority management must remain minimal.
