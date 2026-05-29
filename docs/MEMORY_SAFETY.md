# memory safety

we write the core in c knowing that c is not memory safe.

this document defines the restrictions and processes we use to reduce risk in security-critical code.

strategy
- rely on sel4 for the main isolation boundary
- keep the trusted computing base as small as possible
- enforce strict rules on the c we write in privileged paths
- require static analysis and review for anything touching authority or boundaries
- plan for hardware assistance (cheri) in the long term

we do not claim equivalence to memory-safe languages. we claim a disciplined process that meaningfully lowers the chance and impact of memory safety issues.

scope
strict rules apply to code in the core, capability handling, and anything that crosses system boundaries.

banned in core paths (unless explicitly waived)
- unchecked pointer arithmetic
- memory/string operations on untrusted sizes
- strcpy, sprintf, gets and similar
- variable length arrays and alloca in hot paths
- void* without attached size information

required practices
- buffer sizes must travel with the data
- bounds checks before any access using external lengths
- explicit zeroing of sensitive memory
- clear ownership and deallocation paths

enforcement
changes to core or boundary code must pass static analysis (warnings treated as errors).
core and boundary code requires two-person review.

undefined behavior
we avoid relying on undefined behavior in security-critical code. any exceptions must be isolated, justified, and extra reviewed.

future
cheri (or equivalent) is the intended path to make memory safety a hardware property for c code.

this document will be updated as we gain experience.