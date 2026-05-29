# containment vector interface

real contract under everything

l2 system aka containment vector -/ isolated context
core is only one that can create them or hand out power

-/ lifecycle

create -/ core makes fresh isolated thing - hands initial capabilities per policy
use -/ runs only what it was given
revoke/destroy -/ core takes back or kills whole thing

destruction must be total -/ no leftover rights

-/ authority rules

core - only source of new capabilities
vectors cannot hand power to each other
core can always revoke what it gave

-/ not allowed unless core says so

direct talk between vectors -/ touch host resources -/ allocate outside given set

crossing boundary -/ must go through core -/ must be logged

-/ actual api

only allowed actions from outside are in src/core/sys-h -/ the l2_sys_* functions
if not one of those -/ should not be possible

-/ core invariants

vector only does what current capabilities allow
only core gives new power
revocation is real -/ actually gone
destruction leaves no junk
