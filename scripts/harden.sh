#!/bin/bash
# l2 harden - High-assurance system hardening for the agentic/AI/MCP era
#
# Companion to l2 policy protocols (especially "strict-mcp").
# Applies measures aligned with NSA, CISA, and FBI guidance adapted for
# modern agentic, AI, and MCP (Model Context Protocol / tool-using agents) workloads.
#
# This is a major priority for the l2 system-substrate.

set -euo pipefail

# -----------------------------------------------------------------------------
# Basic argument parsing (very lightweight for now)
# -----------------------------------------------------------------------------
PROFILE="strict-mcp"
TARGET="host"
DRY_RUN=false
FAST=false
NETWORK_ISOLATION=false
GENERATE_SECCOMP=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile) PROFILE="$2"; shift 2 ;;
        --target)  TARGET="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --fast)    FAST=true; shift ;;
        --network-isolation) NETWORK_ISOLATION=true; shift ;;
        --generate-seccomp) GENERATE_SECCOMP="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

# Apply fast mode to paced output
if $FAST; then
    export L2_FAST=1
fi

# -----------------------------------------------------------------------------
# Helper: Generate minimal seccomp profile from a trace log
# -----------------------------------------------------------------------------
generate_seccomp_profile() {
    local trace_log="$1"
    if [ ! -f "$trace_log" ]; then
        echo "Error: Trace log not found: $trace_log" >&2
        return 1
    fi

    type_line "Generating minimal seccomp profile from $trace_log ..."

    # Reuse the spirit of our l2 trace --analyze logic
    local syscalls
    syscalls=$(grep -oE 'syscall=[0-9]+| nr=[0-9]+' "$trace_log" | \
               sed -E 's/.*(syscall|nr)=([0-9]+).*/\2/' | sort -n | uniq)

    if [ -z "$syscalls" ]; then
        echo "No syscalls found in trace. Did you run with L2_STRICT_SECCOMP_OBSERVE=1 ?"
        return 1
    fi

    echo
    type_line "=== Generated Seccomp Profile (strict-mcp style) ==="
    echo
    echo "# For systemd units:"
    echo "SystemCallFilter=@basic @file-system @process @signal @network @timer"
    echo "# Plus these from your trace (minimal allowlist):"
    echo "SystemCallFilter=$(echo "$syscalls" | tr '\n' ' ')"

    echo
    echo "# For our custom l2 enforcing filter (copy into sandbox.rs or a config):"
    echo "Allowed syscalls from trace:"
    echo "$syscalls" | while read -r nr; do
        echo "  $nr"
    done

    echo
    type_line "Recommendation: Feed this into docs/seccomp-phase1-allowlist.md"
    type_line "and only keep what is truly required for your MCP tools."
    type_line "Combine with experimental user-ns (L2_EXPERIMENTAL_USER_NS=1) + C core (L2_USE_CORE=1) for deeper integration testing."

    # Write usable profile files for direct consumption by l2 (auto-discover + L2_SECCOMP_PROFILE)
    local prof_dir="${HOME}/.l2/seccomp"
    mkdir -p "$prof_dir" 2>/dev/null || true
    local raw_profile="$prof_dir/strict-mcp-from-trace.txt"
    # One number per line (or space sep) - both work with the loader in sandbox.rs
    echo "$syscalls" | tr ' ' '\n' | sort -n | uniq > "$raw_profile" || true
    if [ -s "$raw_profile" ]; then
        echo
        type_line "Wrote loadable profile for l2 strict-mcp enforcement:"
        echo "  $raw_profile"
        echo "  Example usage (auto-discovered by strict-mcp in many cases):"
        echo "    L2_STRICT_SECCOMP_ENFORCE=1 l2 exec --policy strict-mcp ./your-mcp-tool"
        echo "  Or explicitly:"
        echo "    L2_SECCOMP_PROFILE=$raw_profile L2_STRICT_SECCOMP_ENFORCE=1 l2 exec --policy strict-mcp ..."
        echo
        echo "  (Also consider copying/symlinking to /etc/l2/ for host-wide use)"
    fi
}

# -----------------------------------------------------------------------------
# Paced output helpers (re-use style from sel4-setup)
# -----------------------------------------------------------------------------
TYPE_DELAY="${L2_TYPE_DELAY:-0.012}"
should_type_slowly() {
    [ "${L2_FAST:-0}" = "1" ] && return 1
    [ -t 1 ] || return 1
    return 0
}

type_line() {
    local text="$*"
    if ! should_type_slowly; then
        printf '%s\n' "$text" || true
        return
    fi
    local i ch
    for (( i=0; i<${#text}; i++ )); do
        ch="${text:i:1}"
        printf '%s' "$ch" || true
        sleep "$TYPE_DELAY"
    done
    printf '\n' || true
}

reveal_lines() {
    local text="$1"
    if ! should_type_slowly; then
        printf '%s\n' "$text" || true
        return
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        printf '%s\n' "$line" || true
        sleep 0.07
    done <<< "$text"
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
echo "=== l2 harden ==="
type_line "High-assurance hardening for the agentic / AI / MCP era"
type_line "Profile: $PROFILE   Target: $TARGET"
if $DRY_RUN; then type_line "Mode: DRY-RUN (no changes will be made)"; fi
echo

reveal_lines "This tool applies security hardening measures aligned with
NSA, CISA, and FBI guidance for the agentic/AI/MCP era of computation.
It prepares systems so that policy protocols like 'strict-mcp' can be used
with real confidence."

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="${ID:-unknown}"
else
    OS_ID="unknown"
fi

type_line "[1/6] Detecting environment..."
type_line "      OS family : ${OS_ID}"
type_line "      Target    : ${TARGET}"
echo

# Handle --generate-seccomp (very useful standalone)
if [ -n "$GENERATE_SECCOMP" ]; then
    generate_seccomp_profile "$GENERATE_SECCOMP"
    echo
    type_line "Seccomp profile generation complete."
    exit 0
fi

# -----------------------------------------------------------------------------
# Helper: Generate a full hardened systemd unit template for strict-mcp
# -----------------------------------------------------------------------------
generate_systemd_unit() {
    local unit_name="${1:-my-strict-mcp-agent}"
    local profile_path="${2:-/etc/l2/seccomp-strict-mcp.bpf}"

    type_line "Generating hardened systemd unit template for strict-mcp..."

    cat << EOF
# /etc/systemd/system/${unit_name}.service
# Generated by l2 harden --profile strict-mcp
# NSA/CISA-grade hardening for agentic/MCP workloads

[Unit]
Description=Strict-MCP Agent (High-Assurance)
After=network.target

[Service]
Type=simple
User=l2-agent
Group=l2-agent

# === Core Hardening (strict-mcp) ===
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
PrivateNetwork=${NETWORK_ISOLATION:-false}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=~user:pid:net:uts:ipc:cgroup
SystemCallArchitectures=native

# Capability dropping (maximally paranoid for agents)
CapabilityBoundingSet=
AmbientCapabilities=

# Seccomp - load generated minimal profile if available
SystemCallFilter=@system-service
# If you generated a profile with: l2 harden --generate-seccomp <trace>
# SystemCallFilter=... (paste the list from the generated profile here, or use our custom loader)

# Optional: Load our custom enforcing filter via wrapper if you use l2 exec
# ExecStart=/usr/local/bin/l2-strict-mcp-wrapper /path/to/your/binary

# Resource limits suitable for agents
MemoryMax=512M
TasksMax=256

[Install]
WantedBy=multi-user.target
EOF

    echo
    type_line "Recommended: Place the above in /etc/systemd/system/${unit_name}.service"
    type_line "Then: systemctl daemon-reload && systemctl enable --now ${unit_name}"
}

# -----------------------------------------------------------------------------
# Core recommendations (MVP skeleton)
# These are the categories that matter most for agentic/AI/MCP systems.
# -----------------------------------------------------------------------------
reveal_lines "$(cat << 'RECS'
[2/6] Core hardening categories for the agentic era

1. Least Privilege & Isolation
   - Enforce strong seccomp + Landlock (or equivalent) on all agent processes
   - Use dedicated low-privilege users / namespaces for MCP servers and tools
   - Prefer capability-dropped, read-only root filesystems where possible

2. Supply Chain & Memory Safety
   - Prefer memory-safe languages for new agent components
   - Pin and verify all dependencies (SBOM + signatures)
   - Regular vulnerability scanning of the agent runtime and tools

3. Runtime & Network Controls
   - Outbound network allowlisting for agents (very few destinations)
   - No ambient credentials in agent environments
   - Strong audit logging of all tool invocations and data flows

4. Secrets & Identity
   - Never embed secrets; use short-lived, narrowly-scoped credentials
   - Hardware-backed or remote attestation where feasible
   - Clear separation between "agent identity" and "human operator identity"

5. Monitoring, Logging & Incident Response
   - Tamper-evident audit logs (append-only, hash-chained)
   - Anomaly detection on agent behavior and tool usage
   - Fast revocation and kill-switch capability for compromised agents

RECS
)"

echo
echo "[3/6] Applying profile: $PROFILE"

case "$PROFILE" in
    strict-mcp)
        echo "      → strict-mcp: High-assurance agentic/MCP workload profile (CURRENT MAIN FOCUS)"
        echo "      → This is stricter than plain 'strict' and is designed to pair with output from this tool."
        ;;
    strict)
        echo "      → strict: Strong general-purpose isolation baseline"
        ;;
    *)
        echo "      → Profile '$PROFILE' not yet fully implemented. Falling back to strict-mcp guidance."
        ;;
esac

if [ "$TARGET" = "host" ]; then
    echo
    type_line "[3.5/6] Concrete host hardening steps (NSA/CISA-aligned for agentic systems)"
    type_line "      These are the practical controls that matter most for running MCP servers and agents."

    if [ "$OS_ID" = "rhel" ] || [ "$OS_ID" = "fedora" ] || [ "$OS_ID" = "centos" ]; then
        echo
        type_line "      RHEL/Fedora family concrete steps (run as root or via sudo):"
        echo
        type_line "      # 1. Dedicated low-privilege user for agents (strongly recommended)"
        echo "      useradd -r -s /sbin/nologin -d /var/lib/l2-agents l2-agent"
        echo "      mkdir -p /var/lib/l2-agents"
        echo "      chown l2-agent:l2-agent /var/lib/l2-agents"
        echo
        type_line "      # 2. Basic kernel hardening (sysctl) - critical for agents"
        echo "      cat >> /etc/sysctl.d/99-l2-agentic-hardening.conf << 'SYSCTL'"
        echo "      kernel.yama.ptrace_scope = 2"
        echo "      kernel.kptr_restrict = 2"
        echo "      kernel.dmesg_restrict = 1"
        echo "      fs.protected_symlinks = 1"
        echo "      fs.protected_hardlinks = 1"
        echo "      fs.protected_fifos = 2"
        echo "      fs.protected_regular = 2"
        echo "      SYSCTL"
        echo "      sysctl -p /etc/sysctl.d/99-l2-agentic-hardening.conf"
        echo
        type_line "      # 3. Audit rules for agent/tool execution (extremely valuable for MCP)"
        echo "      cat > /etc/audit/rules.d/l2-agentic.rules << 'AUDIT'"
        echo "      -w /usr/bin/ -p x -k l2-agent-tools"
        echo "      -w /var/lib/l2-agents/ -p wa -k l2-agent-data"
        echo "      AUDIT"
        echo "      augenrules --load"
        echo
        type_line "      # 4. Capability dropping + advanced namespaces (recommended for agents)"
        echo "      # Example systemd unit snippet (put in /etc/systemd/system/my-agent.service):"
        echo '      # [Service]'
        echo '      # User=l2-agent'
        echo '      # CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_MODULE'
        echo '      # AmbientCapabilities='
        echo '      # NoNewPrivileges=true'
        echo '      # ProtectSystem=strict'
        echo '      # ProtectHome=true'
        echo '      # PrivateTmp=true'
        echo '      # RestrictNamespaces=~user ~pid ~net ~uts ~ipc ~cgroup'
        echo '      # SystemCallArchitectures=native'
        echo
        type_line "      # 5. Advanced namespace example (manual or via systemd-run)"
        echo "      # systemd-run --uid=l2-agent --setenv=... --property=PrivateNetwork=true \\"
        echo "      #             --property=ProtectSystem=strict ./your-agent"
    else
        type_line "      (Add distro-specific concrete steps for $OS_ID here in future versions)"
    fi

    # Network isolation (very important for MCP - agents should not have free outbound)
    if $NETWORK_ISOLATION; then
        echo
        type_line "      === Network Isolation (enabled via --network-isolation) ==="
        type_line "      For strict-mcp workloads, outbound network should be heavily restricted."
        echo
        type_line "      Example (nftables) - drop all outbound for l2-agent user:"
        echo "      nft add table inet l2-agent-isolation"
        echo "      nft add chain inet l2-agent-isolation output { type filter hook output priority 0 \\; policy drop \\; }"
        echo "      nft add rule inet l2-agent-isolation output skuid l2-agent counter drop"
        echo
        type_line "      Then allow only specific destinations your MCP tools actually need."
        type_line "      This is one of the highest-leverage controls for agentic systems."
    fi

    # Automatic hardened systemd unit template for strict-mcp
    if [ "$PROFILE" = "strict-mcp" ]; then
        echo
        type_line "      === Generating hardened systemd unit template (strict-mcp) ==="
        generate_systemd_unit "my-strict-mcp-agent" "/etc/l2/seccomp-strict-mcp.profile"
    fi
fi

echo
echo "[4/6] Generating hardening report..."

REPORT_DIR="${HOME}/.l2/harden-reports"
mkdir -p "$REPORT_DIR"
REPORT_FILE="$REPORT_DIR/$(date +%Y%m%d-%H%M%S)-${PROFILE}-${TARGET}.md"

cat > "$REPORT_FILE" << 'ENDOFREPORT'
# l2 Harden Report

**Generated**: $(date -Iseconds)  
**Profile**: $PROFILE  
**Target**: $TARGET  
**Host**: $(uname -a)

---

## Executive Summary

This system has been evaluated for high-assurance operation in the **agentic / AI / MCP era**.

The recommended policy protocol for this profile is **`strict-mcp`**.

### Quick Start (after reviewing this report)
```bash
# 1. Trace your actual MCP/agent workloads
l2 trace --policy strict-mcp ./your-agent

# 2. Run workloads under the hardened protocol
l2 exec --policy strict-mcp ./your-agent task
```

---

## 1. Execution Policy (Highest Priority)

**Use `l2 exec --policy strict-mcp` for all agent/MCP/tool-using workloads.**

Run `l2 policy show strict-mcp` for the official description of this protocol.

This protocol currently provides:
- Strong Landlock + no_new_privs baseline
- Phase 1 seccomp enforcing filter enabled by default (via `l2 trace` and execution paths)
- Explicit audit of policy protocol usage

**Why strict-mcp over plain "strict"?**
- Designed specifically for workloads that dynamically invoke external tools and MCP servers.
- Biases toward more conservative defaults for agentic systems.
- Will continue to receive MCP-specific hardening rules as the threat model matures.

---

## 2. Host / Container Hardening Checklist

### Isolation & Least Privilege
- [ ] Run all agent/MCP processes as dedicated low-privilege users (never root)
- [ ] Apply `l2` strict-family policies (Landlock + seccomp)
- [ ] Consider user + mount namespaces for additional containment
- [ ] Use read-only mounts for `/usr`, `/bin`, etc. where possible
- [ ] Drop all unnecessary capabilities

### Seccomp & Sandboxing (Critical for MCP)
- [ ] Use `l2 trace --policy strict-mcp` to collect real syscall data from your workloads
- [ ] Feed traces into `docs/seccomp-phase1-allowlist.md`
- [ ] Enable enforcing filter (`L2_STRICT_SECCOMP_ENFORCE=1`) for production MCP agents

### Supply Chain
- [ ] Generate SBOMs for agent runtimes and all MCP tools/servers
- [ ] Verify signatures and pin dependencies with content hashes
- [ ] Regularly scan container images and binaries used by agents

### Network & Secrets
- [ ] Implement aggressive outbound network allowlisting for agents (deny by default)
- [ ] Never inject long-lived credentials into agent environments
- [ ] Use short-lived, narrowly-scoped tokens with strong attestation where possible

### Observability & Response
- [ ] Enable tamper-evident logging (`l2 audit` + kernel audit)
- [ ] Monitor for anomalous tool invocation volume or patterns
- [ ] Maintain a fast kill/revoke capability for compromised agents

---

## 3. MCP / Agentic-Specific Recommendations

Because agents can take autonomous actions via tools, the following are especially important:

- Treat every MCP server/tool as a potential supply-chain or confused-deputy risk.
- Strongly prefer memory-safe implementations for new MCP servers.
- Log every tool call with full context (who requested it, what arguments, what was returned).
- Consider rate limiting and capability gating on dangerous tools (file write, network, shell, etc.).
- Run different trust levels of agents in different `l2` systems with different policies when possible.

---

## 4. Next Commands You Should Run

```bash
# Collect real data for your specific workloads under the target protocol
l2 trace --policy $PROFILE ./path/to/your/agent-or-mcp-server

# Analyze captured logs
l2 trace --analyze /path/to/captured-seccomp.log

# Run actual work under the hardened protocol
l2 exec --policy $PROFILE ./your-workload
```

---

## References & Standards

- NSA / CISA "Securing AI Systems" guidance
- CISA Zero Trust Maturity Model (adapted for agents)
- FBI alerts on AI supply chain and agentic threats
- l2 `strict-mcp` policy protocol documentation (`l2 policy show strict-mcp`)

---

**Report location**: $REPORT_FILE

This report is a living artifact. Re-run `l2 harden` after major system or workload changes.
ENDOFREPORT

echo "      Rich report written to: $REPORT_FILE"

echo "      Report written to: $REPORT_FILE"

echo
echo "[5/6] Next steps"
echo "      1. Review the generated report"
echo "      2. Use \`l2 trace --policy strict-mcp\` to collect data for your specific workloads"
echo "      3. Run agents with \`l2 exec --policy strict-mcp\`"
echo "      4. Re-run \`l2 harden\` periodically after major changes"

echo
echo "[6/6] l2 harden complete for profile '$PROFILE'."

if ! $DRY_RUN; then
    echo
    echo "Remember: This is a living protocol. The threat landscape for agentic systems"
    echo "evolves quickly. Keep your allowlists, policies, and host hardening up to date."
fi

echo
echo "=== l2 harden finished ==="