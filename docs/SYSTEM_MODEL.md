# system model

an l2 system is just a dynamic isolated context that the substrate gives you.

you create it from the terminal, do stuff inside it, and when you're done you tear it down. that's basically it.

## the important bits

- it only exists when you need it
- nothing inside it can touch the host or other systems unless it goes through the functions in sys.h
- the only things you can do are the l2_sys_* calls (create, put, get, exec, destroy, etc)
- the core decides what authority a system actually gets

## how a system lives

1. you call l2_sys_create with some policy
2. you shove things in with l2_sys_put or tell it to run stuff with l2_sys_exec
3. you pull results out with l2_sys_get
4. when you're finished you l2_sys_destroy it and it goes away

if you want to take authority back early you can use l2_sys_revoke.

## how it relates to containment vectors

same thing really. the containment vector doc has the lower level rules. this is just the version normal humans are supposed to think about.

## isolation

inside a system should not be able to read or write the host. one system shouldn't be able to mess with another one. when you destroy it, it should actually be gone (no sneaky leftover capabilities).

everything that crosses the boundary has to be logged in some way.

## backends

on some machines we might actually use sel4 for the real isolation. on your laptop we might use whatever the host gives us (namespaces, seccomp, hypervisor tricks, etc). the interface stays the same either way.
