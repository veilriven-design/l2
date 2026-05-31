# l2 Narrow Protocol (L2P)

**Version 1** (initial)

This document defines the minimal wire protocol between the `l2` terminal client and the l2 substrate core.

The entire point of l2 is the narrowness. The protocol must remain small enough that it can be implemented in disciplined C on the core side and audited easily.

## Goals

- Minimal surface (map directly to the `l2_sys_*` operations)
- Explicit and auditable
- Easy to implement correctly in C and in the client
- Versioned from day one
- Transport agnostic (stdio for MVP, unix socket or vsock later)

## Transport (MVP)

For the first host implementation:

- The `l2` client communicates with the core over **bidirectional stdio** (newline-delimited JSON).
- The client spawns the core (or a development simulator) as a child process, or connects to a long-running core via a unix socket.
- Each message is one JSON object followed by a newline.

Later transports (seL4 IPC, virtio, etc.) will use the same logical messages.

## Message Format

All messages are UTF-8 JSON objects terminated by `\n`.

Every request has:

- `v`: protocol version (integer, currently 1)
- `op`: operation name (string)
- `id`: client-generated request ID (string, for correlation)
- operation-specific fields

Every response has:

- `v`
- `id` (echoed)
- `ok`: boolean
- On success: operation-specific result fields
- On error: `err` (string code) + optional `msg`

## Core Operations

### create

Request:
```json
{"v":1, "op":"create", "id":"c1", "name":"build-42", "policy":"strict"}
```

Success:
```json
{"v":1, "id":"c1", "ok":true, "sys":"sys-9f3a2b", "grants":[]}
```

### destroy

```json
{"v":1, "op":"destroy", "id":"d1", "sys":"sys-9f3a2b"}
```

### put

Places an object into a system.

```json
{"v":1, "op":"put", "id":"p1", "sys":"sys-9f3a2b", "name":"main.c", "type":"code", "data":"...base64 or reference..."}
```

`type` is one of: `data`, `code`, `credential`, `mcp_server` (initial set).

### get

```json
{"v":1, "op":"get", "id":"g1", "sys":"sys-9f3a2b", "name":"result.tar"}
```

Response includes `data` (base64 for small payloads in v1) or a reference.

### exec

```json
{"v":1, "op":"exec", "id":"e1", "sys":"sys-9f3a2b", "what":"./build.sh", "input":"", "timeout_ms":120000}
```

### list

```json
{"v":1, "op":"list", "id":"l1", "sys":"sys-9f3a2b"}
```

### revoke

```json
{"v":1, "op":"revoke", "id":"r1", "sys":"sys-9f3a2b", "grant":"g-abc123"}
```

### ping / status

Lightweight health and version check.

```json
{"v":1, "op":"ping", "id":"ping1"}
```

## Error Codes (initial)

- `invalid`
- `noauth`
- `nospace`
- `notfound`
- `internal`
- `timeout`

## Security & Identity

In the initial host prototype, the core trusts that the client speaking to it on stdio/unix socket is the terminal operator. The client binary itself must be installed with appropriate permissions or run in a context that the operator controls.

Future versions will add:
- Signed requests
- Capability tokens returned by the core
- Explicit session binding

## Versioning & Compatibility

- The protocol is versioned at the message level (`v` field).
- The core must reject unknown major versions cleanly.
- Minor extensions must be additive and optional.

## Implementation Notes for the Core

The core must treat every protocol message as untrusted input. All sizes, names, and data must be validated against the same rules used for the public `l2_sys_*` interface.

No ambient authority is granted through the protocol.

This protocol is deliberately small. If a proposed addition cannot be expressed as a narrow extension to one of the operations above, it is probably out of scope for l2.
