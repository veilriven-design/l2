# system model

l2 system - dynamic isolated context -/ substrate provides it

create from terminal -/ do stuff inside -/ tear down when done

-/ core properties

- only exists on demand
- nothing inside touches host or other systems unless via sys-h functions
- only allowed actions are l2_sys_* calls -/ create / put / get / exec / destroy etc
- core decides authority

-/ lifecycle

l2_sys_create -/ policy
l2_sys_put or l2_sys_exec -/ work inside
l2_sys_get -/ results out
l2_sys_destroy -/ gone

l2_sys_revoke -/ take power back early

-/ relation to containment vector

same thing -/ see containment_vector_interface-md for lower level rules

-/ isolation

no host read/write from inside -/ no cross-system messing -/ clean destruction -/ no leftover capabilities

boundary crossings must be logged

-/ backends

sel4 when possible -/ host primitives otherwise -/ namespaces / seccomp / hypervisor etc
interface stays same
