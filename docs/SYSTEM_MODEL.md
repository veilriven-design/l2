# system model

l2 system - dynamic isolated context

create/use/destroy on demand -/ terminal

-/ properties

- on demand only
- boundary via sys-h only -/ l2_sys_*
- core controls authority

-/ lifecycle

create -/ put/exec -/ get -/ destroy -/ revoke

-/ isolation

no host leak -/ no cross system -/ clean kill -/ logged crossings

-/ backends

sel4 preferred -/ host primitives fallback

same interface
