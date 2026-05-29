# l2

l2 - minimal high-assurance substrate -/ sel4

isolated execution contexts called l2 systems -/ spin up from terminal -/ put stuff in -/ run inside -/ pull results out

nothing leaks unless through narrow interface in src/core/sys-h

systems dynamic -/ create when needed - destroy when done -/ no big background daemon

-/ what it is

- dynamic isolated systems
- tiny interface -/ only l2_sys_* calls
- c with serious guards -/ see memory_safety-md
- operated from normal terminal on host

-/ what its not

- not full os
- not fancy container stuff with all features
- not persistent background thing
- not polished writing

-/ current state

early skeleton -/ core ideas in docs/system_model-md -/ docs/containment_vector_interface-md
code starting in src/

see status-md for actual progress

-/ license

bsd-2-clause -/ see license
