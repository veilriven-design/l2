Containment Vector Interface

This document defines the interface and rules for the Containment Vector, the central abstraction of l2.

The goal is to make the boundary explicit, minimal, and enforceable so that the implementation (in C on top of seL4 or host primitives) can be reviewed and reasoned about with high confidence.

## Purpose

A Containment Vector (realized as an l2 System) provides a strongly isolated execution context. The l2 core is the only entity permitted to create, configure, or destroy vectors.

All authority that crosses the vector boundary must be explicitly granted by the core and is revocable.

## Vector Lifecycle

A vector goes through these phases:

1. Creation — The core allocates an isolated context (e.g. Protection Domain or equivalent) with a fresh set of resources. Initial capabilities are granted according to a declared policy.
2. Configuration — Additional resources and channels are attached only as explicitly requested and authorized.
3. Execution — The vector runs its workload(s) using only the capabilities it holds.
4. Revocation / Destruction — The core can revoke specific capabilities or destroy the entire vector. All resources are reclaimed.

Destruction must be total: no residual authority may remain.

## Authority Model

- Every capability a vector holds is either granted at creation or explicitly delegated later by the core.
- The core always retains the ability to revoke any granted capability.
- Vectors may not create or transfer authority to other vectors without core mediation.

## Boundary Rules

The following are forbidden unless explicitly authorized through the core:

- Direct communication between vectors
- Direct access to host resources
- Creation of new resources outside the vector's allocation

All authorized crossings must be logged.

## Interface

The external operations permitted on a vector are exactly those declared in src/core/sys.h (the l2_sys_* functions).

## Core Invariants

- A vector can only act through the capabilities it currently holds.
- The core is the sole source of new authority.
- Revocation is complete.
- No vector can affect another vector or the host except through core-mediated, auditable paths.
- Destruction leaves no observable residue outside the core.
