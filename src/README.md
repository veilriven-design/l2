# src

c code lives here

model

l2 systems: create / use / kill on demand

all interaction through l2_sys_* functions in sys.h

rules

- keep the public interface tiny
- no leaks across boundaries
- minimal core tcb
- use guards from memory_safety.md

current layout

core/sys.h     - public api
common/safe.*   - memory safety helpers

note: still early and rough