# status

right now we're in the very early skeleton phase.

## what we've done

- basic docs (system_model, containment_vector_interface, memory_safety)
- the main interface lives in src/core/sys.h (all the l2_sys_* functions)
- some memory safety helpers in common/safe.*
- started the core bits

## current direction

we're trying to keep the exposed surface as small as possible. right now the only way to touch a system from the outside is through the functions in sys.h.

no big always-running thing. you make a system when you want one, use it, then kill it.

## next stuff

- actually implement the l2_sys_* calls at least in a basic way
- figure out the cli that sits on top of them
- keep the trusted bits tiny

this is still rough. don't expect nice structure or complete docs yet.
