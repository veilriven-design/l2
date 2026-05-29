# l2 Source Tree

This directory contains the C implementation of the l2 substrate.

## The Treasure Chest Model

From the outside, l2 presents **Treasure Chests** (internally called "systems") — dynamic, strongly isolated environments you interact with from the host terminal.

You create a system, put things in it, make things happen inside it, and pull results out. Nothing inside can affect the host or other systems except through the narrow, explicit operations defined in `sys.h`.

See `docs/TREASURE_CHEST_MODEL.md` for the full mental model.

## Design Principles for the Skeleton

- **Absolute minimal surface**: The only way anything enters, leaves, or acts inside a system is through the operations in `sys.h` (all named `l2_sys_*`).
- **Dynamic creation**: Systems are created and destroyed on demand. No persistent background system is required.
- **Secure by design**: The substrate must make it impossible (or extremely difficult) for anything inside a system to violate the boundary.
- **TCB minimization**: Only the code that implements the system operations and enforces boundaries is privileged.
- **Host integration**: The substrate runs as part of the host environment, using the best available isolation mechanisms (with seL4 providing the strongest guarantees where deployable).

## Current Layout (Early Skeleton)

```
src/
├── README.md
├── core/
│   ├── sys.h             # The complete public surface (l2_sys_create, l2_sys_put, l2_sys_exec, ...)
│   └── core.*            # Implementation of system lifecycle and boundary enforcement
├── common/
│   └── safe.*            # Required memory safety guards (mandatory everywhere in critical paths)
└── vector/
    └── ...               # Code that implements or runs inside systems
```

## Status

We are building the thinnest possible substrate that can faithfully implement the treasure chest / system model while remaining amenable to high-assurance reasoning and future seL4 backing.
