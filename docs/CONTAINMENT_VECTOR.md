# The Containment Vector

The containment vector is the central abstraction of l2.

It is a seL4-enforced, l2-managed execution context with the following properties:

- **Strong isolation**: Spatial and temporal isolation from other vectors and from the host, rooted in seL4 capabilities and address spaces.
- **Explicit authority**: All rights (memory, IPC, device access, host interaction, etc.) are granted via capabilities that are created and revoked only through the l2 core.
- **Effect discipline**: Operations that produce observable effects outside the vector must be authorized according to contracts defined at vector creation or via explicit delegation.
- **Auditability**: Boundary crossings and authority changes are recorded.

## Implementation Approach (Initial)

We use seL4 Microkit protection domains (PDs) as the concrete realization of containment vectors. Each PD receives its own CSpace and VSpace. Communication between vectors and with the host shim occurs only over explicitly declared channels.

The l2 core itself runs in one or more privileged protection domains that hold the authority to create and configure other vectors.

## MCP Integration

MCP servers are instantiated as (or inside) containment vectors. The MCP protocol surface presented to the server is mediated by the vector's granted capabilities. A compromised MCP server cannot reach the host or other vectors beyond what was explicitly allowed when it was started.

This is the primary mechanism by which l2 fulfills its mission of safe MCP management.
