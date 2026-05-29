# The Treasure Chest Model

The user-facing abstraction of l2 is the **Treasure Chest**.

A Treasure Chest is a dynamic, strongly isolated environment on the host system where you can:

- Put things in (data, code, credentials, tools)
- Make things happen inside (execute commands, run MCP servers, perform computation)
- Pull things out (results, artifacts, logs)

**Crucially**: Everything that happens inside a chest is contained. It cannot affect the host system or other chests except through explicit, mediated, and auditable operations provided by l2.

## Mental Model

- The chest itself is the Containment Vector.
- The host terminal is how you interact with chests (create, open, put, exec, get, destroy).
- The l2 substrate enforces the boundary using seL4 where possible, combined with the smallest possible set of host mechanisms to achieve the required isolation on any given platform.
- The surface is deliberately tiny: only the operations you explicitly invoke on a specific chest are possible.

## Core Invariants (from the operator's perspective)

1. What I put into a chest stays in that chest unless I explicitly pull it out.
2. What I run inside a chest cannot read or write anything on the host or in other chests unless I have granted explicit permission for that specific operation.
3. Destroying a chest removes all traces (to the extent possible on the platform).
4. All boundary crossings are logged and attributable to the operator action that caused them.

## Dynamic Nature

Chests are created on demand, used for a purpose, and destroyed when no longer needed. They are not a persistent background system that must be booted. They are tools you reach for when you need a high-assurance workspace.

This is the opposite of a traditional virtual machine or container that runs continuously. A chest is more like a high-security safe that you open, use, and close.

## Relationship to seL4

seL4 provides the strongest available foundation for the isolation properties of a chest. On platforms where a full seL4 instance can be used for a chest, it will be. On other platforms (including the developer's daily macOS or Linux machine), l2 will use the best available host primitives while preserving the same operational model and security properties as closely as possible. The interface and mental model remain identical.

The goal is a consistent "treasure chest" experience regardless of the underlying enforcement mechanism.
