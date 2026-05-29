# Memory Safety and Guard Rules

l2 implements its core in C. Memory safety is treated as a critical engineering requirement, not an optional property.

This document defines the rules, restrictions, and processes that apply to all C code in the project, with the strictest requirements on code that can affect the containment boundary or manage authority.

## Strategy

We accept that standard C is not memory safe. Our defense in depth is:

1. seL4 kernel isolation as the primary boundary
2. Extremely small trusted computing base in userland
3. Rigorous restrictions on the C we write
4. Mandatory static analysis and review gates
5. Explicit future path to hardware-enforced memory safety (CHERI or equivalent)

We do not claim that l2 C code is memory safe in the same sense as Rust or a verified language. We claim it is written and reviewed under a disciplined regime that significantly reduces the likelihood and impact of memory safety bugs in security-critical paths.

## Scope

These rules apply to:
- All code in the l2 core (the code that creates, configures, and destroys containment vectors)
- All code that handles capabilities or crosses containment boundaries
- Any code that runs with elevated authority relative to normal workloads

Less critical code (e.g., certain workload support libraries) may follow relaxed rules, but must be clearly marked and isolated.

## Banned and Restricted Constructs

The following are **banned** in security-critical code unless explicitly waived with documented justification and extra review:

- Unchecked pointer arithmetic
- Use of `memcpy`, `memmove`, `memset` on untrusted or attacker-controlled sizes
- `strcpy`, `strcat`, `sprintf`, `gets` and their variants
- Variable Length Arrays (VLAs) in security-critical paths
- `alloca` or manual stack allocation of attacker-controlled sizes
- Raw `union` type punning for data that may cross boundaries
- Use of `void*` without accompanying size and type information in public interfaces

## Required Guards and Patterns

- All buffers must have explicit size tracking that travels with the pointer.
- Bounds checks must be performed before any access that depends on untrusted input.
- Length parameters must be validated against both maximum and minimum allowed values.
- Use of `const` and `restrict` is mandatory where semantically correct.
- Prefer fixed-size arrays with compile-time known bounds when the maximum size is reasonable.
- All dynamic allocations must have a corresponding, obvious deallocation path under all error conditions.
- Error paths must not leak partially initialized state.

## Static Analysis Requirements

Every change that touches security-critical code must pass the project's mandatory analysis suite before merge. The current required tools are:

- A modern C static analyzer capable of detecting buffer overflows, use-after-free, null dereferences, and integer overflows (e.g., Infer, Frama-C, or CodeQL as adopted by the project).
- Compiler warnings treated as errors (`-Wall -Wextra -Werror` plus seL4-specific warning flags).
- Undefined behavior sanitizer (UBSan) or equivalent in test builds where feasible.

The exact tool configuration and waiver process will be defined in the build system.

## Code Review Requirements

Code that can affect containment or authority requires two-person review, with at least one reviewer having deep familiarity with the current Memory Safety rules and the Containment Vector Interface.

Reviewers must specifically look for:
- Violations of the banned/restricted list
- Missing or insufficient bounds checks
- Incorrect size handling across function boundaries
- Lifetime and ownership issues
- Any use of constructs that could introduce undefined behavior

## Undefined Behavior Policy

No security-critical code may rely on undefined behavior, even if it "works" on the current compiler and platform.

If a construct with potential undefined behavior is required for performance or compatibility reasons, it must be:
- Isolated in the smallest possible module
- Heavily commented with justification
- Covered by additional static analysis and testing
- Approved via the waiver process

## Testing Expectations

- Security-critical modules must have targeted unit tests for boundary conditions (zero length, maximum length, off-by-one, etc.).
- Fuzzing of interfaces that accept data from outside the vector (especially from the host shim) is required before the code is considered mature.
- Where possible, differential testing against a memory-safe reference implementation is encouraged.

## Future Hardening

The project maintains an explicit roadmap toward stronger memory safety guarantees:

- CHERI (or equivalent capability hardware) is the preferred long-term path for making spatial memory safety a hardware-enforced property for C code.
- Gradual adoption of verified or memory-safe components in non-performance-critical parts of the core is acceptable when they can be cleanly isolated.
- The architecture must not assume the absence of CHERI or similar hardware in the long term.

## Maintenance

This document is living. Any proposed relaxation of these rules requires explicit discussion and update to this file. The default position is that the rules only become stricter over time for security-critical code.
