# memory safety

we're writing the important parts in c. c is not memory safe. we're not pretending it is.

this file is the rules we actually follow so we don't shoot ourselves in the foot too badly.

## basic strategy

1. sel4 does the heavy isolation lifting
2. we keep the trusted bits tiny
3. we have strict rules about what c we're allowed to write
4. static analysis + review on anything that touches authority or boundaries
5. someday we want cheri or something similar to make this actually safe in hardware

we're not claiming this is as good as rust. we're claiming it's better than the usual "just write some c and hope" approach.

## what has to follow the rules

- anything in the core that creates or manages systems
- anything that deals with capabilities or crosses system boundaries
- anything that runs with more power than a normal workload

normal workload code can be sloppier, but it should still be marked.

## things that are mostly banned in the core

- raw pointer arithmetic without checks
- memcpy/memmove on sizes that came from outside
- strcpy, sprintf, gets, etc.
- vlas in hot paths
- alloca with untrusted sizes
- void* with no size info attached

## things we actually require

- sizes travel with buffers
- bounds checks before using untrusted lengths
- explicit zeroing when we need to clear stuff
- const and restrict where they make sense
- clear ownership and cleanup paths

## analysis

every change that touches the core or boundaries has to pass static analysis. warnings are errors. we want something like infer or codeql or frama-c in the loop.

## review

core and boundary code needs two sets of eyes. at least one person should actually care about the memory safety rules when they look at it.

## undefined behavior

we try really hard not to rely on it in the important code. if we have to do something sketchy, it needs to be tiny, commented, and extra reviewed.

## future

cheri is the real long term plan for making c not suck at this. until then we do the best we can with process and tooling.

this doc will change as we learn what actually hurts.
