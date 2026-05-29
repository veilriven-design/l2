# l2 Source Tree

This directory contains the C implementation of the l2 substrate.

## The Treasure Chest Model

From the outside, l2 presents **Treasure Chests** — dynamic, strongly isolated environments you interact with from the host terminal.

You create a chest, put things in it, make things happen inside it, and pull results out. Nothing inside can affect the host or other chests except through the narrow, explicit operations defined in `chest_ops.h`.

See `docs/TREASURE_CHEST_MODEL.md` for the full mental model.

## Design Principles for the Skeleton

- **Absolute minimal surface**: The only way anything enters, leaves, or acts inside a chest is through the operations in `chest_ops.h`.
- **Dynamic creation**: Chests are created and destroyed on demand. No persistent background system is required.
- **Secure by design**: The substrate must make it impossible (or extremely difficult) for anything inside a chest to violate the boundary.
- **TCB minimization**: Only the code that implements the chest operations and enforces boundaries is privileged.
- **Host integration**: The substrate runs as part of the host environment, using the best available isolation mechanisms (with seL4 providing the strongest guarantees where deployable).

## Current Layout (Early Skeleton)

```
src/
├── README.md
├── core/
│   ├── chest_ops.h     # The complete public surface for any chest
│   └── core.*          # Implementation of chest creation and boundary enforcement
├── common/
│   └── safe.*          # Required memory safety guards (mandatory everywhere in critical paths)
└── vector/
    └── ...             # Code that implements or runs inside chests
```

## Status

We are building the thinnest possible substrate that can faithfully implement the treasure chest model while remaining amenable to high-assurance reasoning and future seL4 backing.
