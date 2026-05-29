System Model

An l2 System is a dynamic, isolated execution context provided by the l2 substrate.

## Core Properties

- **Dynamic**: Systems are created and destroyed on demand via the host terminal. There is no persistent background daemon or always-running environment required.
- **Isolated**: Code and data inside an l2 System have no direct access to the host or to other l2 Systems. All interaction with the outside world must occur through the narrow, explicit interface defined in src/core/sys.h.
- **Minimal Surface**: The complete set of operations permitted on an l2 System is defined by the l2_sys_* functions. No other effects are possible through the substrate.
- **Authority-Controlled**: All capabilities and resources granted to a system are explicitly allocated by the l2 core at creation time or through subsequent l2_sys_revoke / delegation operations.

## Lifecycle

1. Creation (l2_sys_create): The substrate allocates a new isolated context with a declared policy. The caller receives an opaque handle (l2_sys_t).
2. Population and Use: The operator may use l2_sys_put, l2_sys_exec, and related operations to introduce objects and trigger computation inside the system.
3. Observation: Results and artifacts may be retrieved only via l2_sys_get and l2_sys_list.
4. Revocation and Destruction: Authority may be revoked at any time. l2_sys_destroy reclaims all resources associated with the system.

## Relationship to Containment Vector

An l2 System is the concrete realization of a Containment Vector (see docs/CONTAINMENT_VECTOR_INTERFACE.md). The interface in sys.h is the external contract; the internal enforcement is the responsibility of the l2 core and the underlying isolation mechanisms (seL4 where available, supplemented by host primitives).

## Isolation Guarantees

The substrate must ensure that:
- Execution inside an l2 System cannot read or write host resources except through mediated l2_sys_* calls.
- One l2 System cannot affect another except through explicit, logged operations.
- Destruction of an l2 System leaves no residual authority or observable state outside the core.

All boundary crossings are required to be auditable.

## Implementation Backends

The l2 core may realize an l2 System using different enforcement mechanisms depending on the host platform and assurance requirements:
- Full seL4-based isolation (strongest guarantees).
- Microkernel or hypervisor primitives.
- Host OS sandboxing mechanisms (namespaces, capabilities, virtualization, etc.) with additional hardening.

The external interface (l2_sys_*) and security properties remain the same regardless of backend.
