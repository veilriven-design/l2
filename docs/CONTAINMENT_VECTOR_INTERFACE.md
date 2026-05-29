# containment vector interface

core contract

l2 system = containment vector -/ isolated -/ core only creator

-/ lifecycle

create -/ policy + initial caps
use -/ only given caps
revoke/destroy -/ total -/ no leftovers

-/ rules

core = only authority source
no direct vector-vector
no unauthorized host touch

cross = core + logged

-/ api

only l2_sys_* in sys-h

-/ invariants

vector = current caps only
core = sole grantor
revoke = real
destroy = clean
