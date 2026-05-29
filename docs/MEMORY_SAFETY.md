# memory safety

important parts in c -/ c is not memory safe -/ we are not pretending

this file -/ rules we follow so we dont fuck up too bad

-/ basic approach

sel4 -/ heavy isolation
keep trusted bits tiny
strict rules on allowed c
static analysis + review on authority/boundary code
future -/ cheri or similar for real hardware safety

not claiming rust level -/ claiming better than normal c and hope

-/ must follow rules

core -/ creates/manages systems
capability and boundary crossing code
elevated authority code

normal workloads can be sloppier -/ should still be marked

-/ mostly banned in core

raw pointer arithmetic without checks
memcpy on untrusted sizes
strcpy / sprintf / gets etc
vlas in hot paths
alloca with attacker sizes
void* with no size attached

-/ required

sizes travel with buffers
bounds checks before untrusted lengths
explicit zeroing
const/restrict where sensible
clear ownership + cleanup

-/ analysis

every boundary/core change -/ must pass static analysis
warnings as errors -/ infer/codeql/frama-c etc wanted

-/ review

core/boundary code -/ two person review
at least one must care about these memory rules

-/ undefined behavior

try hard not to rely on it in important code
if must -/ tiny + heavily commented + extra review

-/ future

cheri -/ real long term fix for c
until then -/ process + tooling

this doc changes as we learn what actually hurts
