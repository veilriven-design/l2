# l2

l2 is a minimal high-assurance substrate on top of sel4.

it gives you isolated execution contexts called l2 systems. you spin one up from the terminal, put stuff in it, run things inside it, and pull results out. nothing inside leaks out unless it goes through the narrow interface in src/core/sys.h.

systems are dynamic — you create them when you need them and destroy them when you're done. no big background thing running all the time.

## what it is

- dynamic isolated systems
- tiny interface (just the l2_sys_* calls)
- written in c but with serious guards (see memory_safety.md)
- meant to be operated from a normal terminal on your machine

## what it's not

- not a full os
- not trying to be a fancy container runtime with all the features
- not a thing that stays running in the background
- not polished academic writing

## current state

early skeleton. the core ideas are in docs/system_model.md and docs/containment_vector_interface.md. code is starting in src/.

see status.md for what's actually done.

## license

bsd-2-clause (see license)
