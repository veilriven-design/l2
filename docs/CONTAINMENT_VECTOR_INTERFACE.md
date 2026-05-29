# containment vector interface

this is the real contract underneath everything.

an l2 system (aka containment vector) is an isolated context. the core is the only thing allowed to make them or give them power.

## lifecycle (roughly)

- create: core makes a fresh isolated thing and hands out the initial capabilities according to whatever policy you asked for
- use: it runs whatever you put in it, using only what it was given
- revoke/destroy: core can take capabilities back or just kill the whole thing

destruction has to be complete. no leftover rights hanging around.

## authority rules

- the core is the only source of new capabilities for a vector
- vectors can't just hand power to each other
- anything the core gives can be taken back

## what is not allowed

unless the core explicitly says so, a vector cannot:
- talk directly to other vectors
- touch host resources
- allocate new stuff outside what it was given

if it does cross the boundary it has to go through the core and it has to be logged.

## the actual api

all the things you're allowed to do from outside are in src/core/sys.h. that's it. if it's not one of the l2_sys_* functions, it shouldn't be possible.

## invariants the core has to maintain

- a vector can only do what its current capabilities allow
- only the core can give new power
- when something is revoked it's actually gone
- destroying a vector doesn't leave junk behind
