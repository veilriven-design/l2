# l2

minimal high-assurance sel4 substrate

l2 systems are isolated contexts

create from terminal
put things in / run code inside / pull results out

only through l2_sys_* calls (src/core/sys.h)

no leaks to host or other systems
no persistent background daemon

what it is
- dynamic (on demand)
- tiny interface
- c with memory guards (see memory_safety.md)
- works from normal terminal on any host

what it's not
- full general purpose os
- heavy container platform
- always-running service

current state: early skeleton

core docs: system_model.md + containment_vector_interface.md

see status.md

license: bsd-2-clause