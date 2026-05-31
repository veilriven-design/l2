# Status

**Refocused narrow substrate phase** (post-Latticra distillation)

## Charter

l2 is the minimal high-assurance Latticra substrate:
- Dynamic, on-demand isolated execution contexts
- Driven exclusively from the terminal (CLI/TUI primary interface)
- Tiny public surface (`l2` command + `l2_sys_*`)
- Total cleanup on destroy
- Extreme restraint on scope and code

## Done

- New focused charter and invariants (see README)
- Terminal-first design direction locked
- Initial `l2_sys_*` interface shape
- Basic memory safety guards (`src/common/safe.*`)
- Early skeletal core layout

## Current Focus

1. **Terminal CLI/TUI surface** (highest priority)
   - Define crisp command set and interaction model
   - Make the daily experience feel like a high-quality, direct tool (Grok Build TUI spirit)
2. Implement the narrow `l2_sys_*` surface against the new model
3. Host-side shim (initially a small CLI binary) that speaks the protocol

## Next (strict order)

- Write the terminal interface design document
- Prune docs/ and src/ to the minimal necessary set
- Implement core create/put/exec/get/destroy path (host backend first for speed)
- seL4/Microkit backend as the strong-isolation target

## Explicitly Out of Scope (for now and likely forever in l2)

- Effect systems, lattices, multi-model frameworks
- Packaging, installers, distribution contracts
- Physics, proof objects, or simulation work
- Large documentation suites or layered architecture models

Keep it small. Keep it terminal. Keep it high-assurance.

Work in progress — moving deliberately.
