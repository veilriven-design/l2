# memory safety

core in c -/ not safe -/ rules to limit damage

-/ approach

sel4 isolation
minimal tcb
strict c rules
analysis + review on boundaries
cheri long term

-/ scope

core + boundary + elevated code

-/ banned in core

unchecked ptr arith
memcpy on external sizes
strcpy/sprintf/gets
vlas/alloca untrusted
void* no size

-/ required

sizes with buffers
bounds checks
zeroing
clear cleanup

-/ enforcement

static analysis required
warnings=errors
2-person review on core

no ub in critical paths unless tiny+reviewed

-/ future

cheri

changes as we learn
