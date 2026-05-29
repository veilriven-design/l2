# l2 Source Tree

This directory contains the C implementation of the l2 substrate.

## Model

l2 provides dynamic isolated execution contexts called l2 Systems. Each system is created and destroyed on demand. All interaction with a system occurs exclusively through the narrow interface in sys.h (the l2_sys_* functions).

See docs/SYSTEM_MODEL.md for the technical definition.

## Design Principles

- Absolute minimal interface: only l2_sys_* operations are exposed.
- Dynamic lifecycle with no requirement for persistent background components.
- Strong containment enforced by the substrate.
- TCB minimization for all code that can create or affect systems.
- Host integration with seL4 used for strongest isolation where feasible.

## Current Layout

```
src/
├── README.md
├── core/
│   ├── sys.h            # Public interface (l2_sys_create, l2_sys_put, l2_sys_exec, ...)
│   └── core.*           # Core implementation of system management and enforcement
├── common/
│   └── safe.*           # Mandatory memory safety utilities
└── vector/
    └── ...              # Support for code executing inside systems
```

## Status

Early code skeleton focused on the l2 System abstraction and its minimal interface.
