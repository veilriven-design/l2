# sel4 coupling

l2 system substrate couples directly to sel4 as verified kernel base

l2 core runs privileged in sel4 userland

- creates dynamic l2 systems as sel4 protection domains (or microkit pd equivalent)
- controls capability distribution for strict isolation
- implements l2_sys_* interface using sel4 primitives (cspace vspace ipc notifications)

systems get fresh cspace and vspace on creation
core retains revocation power over all granted caps

host integration

sel4 runs in locked vm on developer hosts
narrow channel (vsock or equivalent) from host terminal shim to l2 core
l2 systems live as isolated sel4 contexts inside the vm

on high assurance deployments direct sel4 on hardware preferred

minimal surface maintained by exposing only l2_sys_* calls

sel4 formal guarantees (isolation correctness) form the foundation for l2 high assurance claims

c coupling

l2 core and system code written in guarded c on top of sel4runtime
memory safety rules in memory_safety.md apply to all l2 userland

see system_model.md and containment_vector_interface.md for higher level model