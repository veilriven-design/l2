# Terminal Interface Design

This document defines the **terminal experience** for l2. It is the most important design artifact because the terminal is the primary (and for a long time, only) way anyone will use the substrate.

## Philosophy (Grok Build TUI spirit)

- Direct. You type a command and something clear happens.
- Precise. Flags and arguments are explicit when they matter; strong sensible defaults otherwise.
- Low friction. Common workflows are short and memorable.
- Scriptable first. Every operation must be usable from scripts and Makefiles without parsing human text.
- Delightful interactively. When a human is at the keyboard, the tool can offer light interactivity, good help, and clear visual feedback.
- No magic. Every boundary crossing or authority grant is visible.

The tool should feel like a well-crafted systems tool (think: `git`, `podman` in some modes, or a high-quality internal CLI), not an application.

## Command Structure

```bash
l2 <command> [subcommand] [arguments] [options]
```

### Core Commands (stable surface)

| Command     | Purpose                                      | Example                              |
|-------------|----------------------------------------------|--------------------------------------|
| `create`    | Create a new isolated system                 | `l2 create build-42 --policy strict` |
| `destroy`   | Destroy a system (total cleanup)             | `l2 destroy build-42`                |
| `put`       | Place an object into a system                | `l2 put build-42 code ./src`         |
| `get`       | Retrieve an object or result from a system   | `l2 get build-42 result.tar`         |
| `exec`      | Execute work inside a system                 | `l2 exec build-42 ./build.sh`        |
| `list`      | List systems or objects inside one           | `l2 list` or `l2 list build-42`      |
| `revoke`    | Remove specific authority from a system      | `l2 revoke build-42 cap-1234`        |
| `status`    | Show substrate and system state              | `l2 status` or `l2 status build-42`  |

### Global Options

- `--help`, `-h`
- `--json` — machine-readable output for scripting
- `--quiet` / `--verbose`
- `--host-backend` (for development: qemu, native, etc.)

## Interaction Styles

### 1. One-shot CLI (primary for scripts and muscle memory)

```bash
l2 create mcp-review --policy mcp-default
l2 put mcp-review code ./review-agent
l2 exec mcp-review "cargo test --quiet"
l2 get mcp-review "report.md" > review-report.md
l2 destroy mcp-review
```

### 2. Lightweight Interactive / TUI Mode

When run with no arguments or with an explicit `l2 shell` / `l2 interactive` mode:

- Present a clean prompt in the context of the current substrate session.
- Tab completion for system names and common objects.
- Shortcuts for the most common verbs.
- Live status of running systems (lightweight, not a daemon).
- Easy escape back to normal shell.

The interactive mode should feel like an elevated REPL over the substrate, not a full graphical application.

## Output Principles

- Human output is clear, structured, and greppable.
- Machine output (`--json`) is always available and stable.
- Errors are actionable and never silent.
- Success is explicit (or silent in quiet mode for scripting).

## Security & Audit Surface

Every `l2` invocation that grants or exercises authority must be able to log:

- Timestamp, operator identity (where available)
- Exact command and arguments
- Target system
- Result (success/failure + any grant IDs created)

The substrate core (not just the CLI) is the source of truth for authority decisions. The CLI is a thin, auditable translator.

## Non-Goals

- Rich graphical interfaces (someone else can build on the narrow protocol later)
- Complex configuration files or "projects"
- Long-running client-side agents

## Implementation Notes

- Initial host implementation: small native binary (C or Rust) or a very small Go binary.
- Protocol between `l2` client and substrate core must be narrow, versioned, and designed for analysis.
- The client itself must never hold raw authority — it only forwards signed/authorized requests from the terminal operator.

This document is the north star for the user experience. Code and other docs must align to it.
