# l2 Source Tree

This directory contains the C implementation of the l2 substrate.

## Design Principles for the Skeleton

- **Minimize the TCB**: Only the absolute minimum code required to create, manage, and enforce containment vectors lives in privileged protection domains.
- **Enforce the rules**: Every file must follow the restrictions and patterns defined in `docs/MEMORY_SAFETY.md`.
- **Clear boundaries**: Code that can create or affect vectors is separated from code that runs inside vectors.
- **No unnecessary abstraction**: We use seL4 Microkit primitives directly where possible.
- **Auditability**: All authority changes and boundary crossings must be traceable.

## Current Layout (Early Skeleton)

```
src/
├── README.md          # This file
├── core/              # The l2 core - creates and manages containment vectors
│   └── ...
├── common/            # Shared safe utilities and guards (must be extremely small)
│   └── ...
└── vector/            # Support code that can run inside or help define vectors
    └── ...
```

Workloads (MCP servers, etc.) will eventually live in their own protection domains and only receive capabilities explicitly granted by the core.

## Build Status

This is currently a skeleton. The first goal is to produce a minimal bootable seL4 + Microkit system under QEMU that demonstrates the core protection domain running and able to create a simple containment vector.

See `docs/BUILD.md` and the top-level STATUS.md for current progress.
