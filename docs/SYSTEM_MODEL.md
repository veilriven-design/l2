# system model

an l2 system is a dynamic isolated execution context provided by the substrate.

systems are created and destroyed on demand from the terminal.

properties
- dynamic lifecycle
- strict isolation: nothing crosses the boundary except through the l2_sys_* interface in sys.h
- authority is controlled by the core

lifecycle
- l2_sys_create with policy
- l2_sys_put / l2_sys_exec to work inside
- l2_sys_get to retrieve results
- l2_sys_destroy when finished
- l2_sys_revoke to remove specific authority early

isolation guarantees
execution inside a system cannot directly affect the host or other systems.
all boundary crossings must be explicit and auditable.

destruction must leave no residual capabilities.

backends
on suitable hardware we use sel4 for strong isolation.
on normal developer machines we use the best available host mechanisms (namespaces, virtualization, etc).

the external interface remains the same regardless of backend.

see sel4_coupling.md for details on how l2 couples to sel4 primitives.