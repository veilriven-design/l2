# Contributing to l2

l2 is a high-assurance project. Precision and restraint matter more than velocity.

## General Rules

- Every addition must be justified against the mission: minimal high-assurance containment for MCP and developer computation on host terminals.
- Changes that touch the containment boundary, capability management, the host protocol, or any code that can grant or exercise authority require extra review.
- Prefer deleting or avoiding code over adding it.

## Code Style (C)

- Follow the seL4 coding conventions and the stricter rules defined in the project security process (to be elaborated).
- All security-relevant code must pass the project's static analysis gates before merge.

## Documentation

Keep it tight. One well-written paragraph is preferred over several vague ones.

## Security

See `SECURITY.md`. Vulnerabilities affecting containment or authority are critical.

## First Steps

Until the first implementation milestone is reached, most contributions will be in the form of architecture clarification, threat model refinement, or build environment improvements.
