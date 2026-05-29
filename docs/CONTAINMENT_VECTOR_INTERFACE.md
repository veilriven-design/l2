# Containment Vector Interface

This document defines the interface and rules for the **Containment Vector**, the central abstraction of l2.

The goal is to make the boundary explicit, minimal, and enforceable so that the implementation (initially in C on seL4 Microkit) can be reviewed and reasoned about with high confidence.

## Purpose

A Containment Vector provides a strongly isolated execution context in which workloads (MCP servers, developer tasks, etc.) run under strictly limited authority. The l2 core is the only entity permitted to create, configure, or destroy vectors.

All authority that crosses the vector boundary must be explicitly granted by the core and is revocable.

## Vector Lifecycle

A vector goes through these phases:

1. **Creation** — The core allocates a Protection Domain (PD) with a fresh CSpace and VSpace. Initial capabilities are granted according to a declared policy for that vector.
2. **Configuration** — Additional capabilities, channels, and shared memory regions are attached as requested by the operator (via the host terminal) and approved by policy.
3. **Execution** — The vector runs its workload(s). Only the capabilities it holds are usable.
4. **Revocation / Destruction** — The core can revoke specific capabilities or destroy the entire vector. All resources are reclaimed.

Destruction must be total: no residual authority or communication channels may remain.

## Authority Model

- Every capability a vector holds is either:
  - Granted at creation time (minimal baseline), or
  - Explicitly delegated later by the core.
- The core always retains the ability to revoke any capability it has granted.
- Vectors may not mint or transfer capabilities to other vectors without core mediation.
- Workloads inside a vector see only the capabilities exposed to them through the vector's CSpace.

MCP servers should typically receive extremely narrow authority (e.g., specific IPC endpoints, limited shared memory regions, and mediated access to host services).

## Boundary Rules

The following are forbidden unless explicitly authorized through the core:

- Direct IPC or shared memory between vectors
- Access to host resources (filesystem, network, devices)
- Creation of new threads or address spaces outside the vector's allocation
- Sending data or signals to the host except through approved channels

All authorized crossings must be logged at the core level with sufficient context for audit.

## Workload Instantiation

When starting a workload inside a vector:

- The core creates (or reuses) a vector with a policy matching the workload type.
- The workload binary/image is loaded into the vector's address space.
- Only the declared minimal capabilities are present at start.
- For MCP servers, the MCP protocol surface is provided only through a mediated interface defined by the granted capabilities.

A compromised workload must not be able to expand its authority beyond what was granted at instantiation.

## Host Terminal Interface Obligations

The host shim may only request the following operations on vectors:

- Create vector with a declared policy
- Start a specific workload inside a vector
- Revoke specific capabilities from a vector
- Destroy a vector
- Query limited, non-sensitive status information

The core is responsible for enforcing policy and auditing. The host shim must not be able to bypass the core.

## Core Invariants

These must hold for any correct implementation:

- A vector can only act through the capabilities it currently holds.
- The core is the sole source of new authority into any vector.
- Revocation is complete and timely.
- No vector can affect another vector or the host except through core-mediated, auditable paths.
- Destruction of a vector leaves no observable residue outside the core.

## Status

This is an initial definition. It will be refined as the implementation and threat model analysis proceed. Changes that affect the invariants or the set of allowed boundary crossings require careful review.
