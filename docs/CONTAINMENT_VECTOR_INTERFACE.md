# containment vector interface

this defines the core rules for l2 systems (also called containment vectors).

an l2 system is an isolated context. only the core can create them and grant authority.

lifecycle
- creation: core allocates the context and grants initial capabilities based on policy
- use: the system can only act with the capabilities it currently holds
- revocation and destruction: the core can remove capabilities or destroy the entire system at any time

destruction must be complete with no residual authority left behind.

authority model
- the core is the sole source of new capabilities for any system
- systems cannot directly transfer authority to each other
- any capability granted by the core can be revoked

boundary rules
unless explicitly authorized by the core, a system may not:
- communicate directly with other systems
- access host resources
- allocate resources outside its assigned set

any authorized crossing of the boundary must be mediated by the core and logged.

public interface
all external operations on systems are defined in src/core/sys.h using the l2_sys_* functions.

core invariants
- a system can only perform actions allowed by its current capabilities
- only the core can introduce new authority
- revocation is effective
- destruction leaves the system fully cleaned up with no external side effects