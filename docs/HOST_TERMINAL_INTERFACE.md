# Host Terminal Interface

l2 is designed to be usable from the ordinary terminal on any host operating system that can run a terminal emulator and a virtual machine (QEMU or equivalent).

## Model

- A small host-side shim (initially a command-line tool) speaks a narrow, authenticated, versioned protocol to the l2 substrate running inside the seL4 guest.
- All developer operations — creating containment vectors, starting MCP servers, inspecting state, revoking authority — are expressed as commands in this terminal.
- The shim itself must be minimal and auditable. On POSIX hosts it will be a small C or Rust binary; on Windows it may be a small native binary or WSL intermediary.

## Invariants

- The host shim never holds authority to create or modify containment vectors directly. It only forwards signed/authorized requests from the terminal operator.
- The protocol between shim and l2 core is intentionally small and designed for formal or semi-formal analysis over time.
- No general filesystem or network access from the host into the containment vectors is provided except through explicitly mediated, logged channels.

The terminal is the universal developer surface. Everything else (GUIs, IDE integrations, etc.) is built on top of this narrow interface later, if at all.
