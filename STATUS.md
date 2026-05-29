# status

early skeleton phase

-/ what we have so far

- basic docs -/ system_model - containment_vector_interface - memory_safety
- main interface in src/core/sys-h -/ all l2_sys_* functions
- memory safety helpers in common/safe-*
- core bits started

-/ current direction

keep exposed surface tiny -/ only way to touch system from outside is via functions in sys-h

no persistent background -/ make system when needed - use it - kill it

-/ next

- implement l2_sys_* calls basically
- cli on top of the interface
- keep trusted core minimal

still rough -/ dont expect clean structure yet
