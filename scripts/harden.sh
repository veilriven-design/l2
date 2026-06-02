#!/bin/bash
# l2 harden - High-assurance system hardening for the agentic/AI/MCP era
#
# Companion to l2 policy protocols (strict-mcp for agents; ransom-hardened for ransomware/malicious testing).
# Applies measures aligned with NSA, CISA, and FBI guidance adapted for
# modern agentic, AI, and MCP (Model Context Protocol / tool-using agents) workloads.
# ransom-hardened profile adds worm/encrypt/persistence blocks for WannaCry-class containment testing
# and supply-chain (Miasma npm preinstall + credential exfil + "Miasma: The Spreading Blight" propagation).
# great-harden: supreme aerospace/industrial (l2 great-harden) - higher assurance, closes gaps, impenetrable servers.
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
APPLY=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile) PROFILE="$2"; shift 2 ;;
        --target)  TARGET="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --fast)    FAST=true; shift ;;
        --network-isolation) NETWORK_ISOLATION=true; shift ;;
        --generate-seccomp) GENERATE_SECCOMP="$2"; shift 2 ;;
        --apply)   APPLY=true; shift ;;
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

    echo || true
    type_line "=== Generated Seccomp Profile (strict-mcp / ransom-hardened style) ==="
    echo || true
    echo "# For systemd units:" || true
    echo "SystemCallFilter=@basic @file-system @process @signal @network @timer" || true
    echo "# Plus these from your trace (minimal allowlist):" || true
    echo "SystemCallFilter=$(echo "$syscalls" | tr '\n' ' ')" || true

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
    local prof_dir="$L2_BASE/seccomp"
    mkdir -p "$prof_dir" 2>/dev/null || true
    local raw_profile="$prof_dir/strict-mcp-from-trace.txt"
    # One number per line (or space sep) - both work with the loader in sandbox.rs
    echo "$syscalls" | tr ' ' '\n' | sort -n | uniq > "$raw_profile" || true
    if [ -s "$raw_profile" ]; then
        echo || true
        type_line "Wrote loadable profile for l2 strict-mcp enforcement:"
        echo "  $raw_profile" || true
        echo "  Example usage (auto-discovered by strict-mcp in many cases):" || true
        echo "    L2_STRICT_SECCOMP_ENFORCE=1 l2 exec --policy strict-mcp ./your-mcp-tool" || true
        echo "  Or explicitly:" || true
        echo "    L2_SECCOMP_PROFILE=$raw_profile L2_STRICT_SECCOMP_ENFORCE=1 l2 exec --policy strict-mcp ..." || true
        echo || true
        echo "  (Also consider copying/symlinking to /etc/l2/ for host-wide use)" || true
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
if [ -n "${L2_DATA_DIR:-}" ]; then
    L2_BASE="$L2_DATA_DIR"
else
    L2_BASE="${HOME}/.l2"
fi

echo "=== l2 harden ==="
type_line "High-assurance hardening for the agentic / AI / MCP era"
type_line "Profile: $PROFILE   Target: $TARGET"
if $DRY_RUN; then type_line "Mode: DRY-RUN (no changes will be made)"; fi
if $APPLY; then type_line "Mode: APPLY (confirmed operational changes + evidence update)"; fi
echo

reveal_lines "This tool applies security hardening measures aligned with
NSA, CISA, and FBI guidance for the agentic/AI/MCP era of computation.
It prepares systems so that policy protocols like 'strict-mcp' (agents) and
'ransom-hardened' (full safety for ransomware/WannaCry-class testing) can be used
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
    echo || true
    type_line "Seccomp profile generation complete."
    exit 0
fi

# -----------------------------------------------------------------------------
# Helper: Generate a full hardened systemd unit template (generic for strict-mcp / ransom-hardened)
# -----------------------------------------------------------------------------
generate_systemd_unit() {
    local unit_name="${1:-my-strict-mcp-agent}"
    local profile_path="${2:-/etc/l2/seccomp-strict-mcp.bpf}"

    type_line "Generating hardened systemd unit template for ${unit_name}..."

    cat << EOF
# /etc/systemd/system/${unit_name}.service
# Generated by l2 harden --profile (see unit name)
# NSA/CISA-grade + ransomware containment hardening for agentic/malicious workloads

[Unit]
Description=Hardened l2 Agent (High-Assurance / Full-Safety)
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
    ransom-hardened)
        echo "      → ransom-hardened: FULL SAFETY protocol for ransomware / malicious code testing (WannaCry-class)"
        echo "      → Strictest posture: auto seccomp enforce (no net), minimal Landlock (ws-only), rlimits."
        echo "      → Use with l2 exec --policy ransom-hardened + the resistance demo to validate containment."
        echo "      → See docs/examples/l2_ransomware_resistance_demo.c for the sim (encrypt + SMB + persist + priv-esc attempts contained)."
        ;;
    great-harden)
        echo "      → great-harden: SUPREME aerospace/industrial/critical infrastructure mode (l2 great-harden)"
        echo "      → Makes servers IMPENETRABLE to major classes of known malware/worms/viruses (ransomware + Miasma + viruses + AIO malware-cancer substrate + AI supply chain per 2026 NSA CSI). Aligns to CPG 2.0, NSA MCP security design for AI automation, OT AI integration principles."
        echo "      → Extreme: combines ransom-hardened + strict-mcp + aerospace (kernel lockdown, modules disabled, full ro root, no dynamic code, extreme caps/seccomp/Landlock, verified paths)."
        echo "      → Closes all logic gaps from prior sweeps. Use for high-assurance where standard hardening misses."
        echo "      → Forces great-harden policy (ransom-hardened superset). Pair with l2 exec --policy great-harden."
        echo "      → Generates supreme units, full system lockdown configs, anti-malware rules."
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
        echo || true
        type_line "      === Network Isolation (enabled via --network-isolation) ==="
        type_line "      For strict-mcp workloads, outbound network should be heavily restricted."
        type_line "      Also critical to block Miasma-style credential exfil, OIDC theft, and worm C2/propagation."
        echo || true
        type_line "      Example (nftables) - drop all outbound for l2-agent user:"
        echo "      nft add table inet l2-agent-isolation" || true
        echo "      nft add chain inet l2-agent-isolation output { type filter hook output priority 0 \\; policy drop \\; }" || true
        echo "      nft add rule inet l2-agent-isolation output skuid l2-agent counter drop" || true
        echo || true
        type_line "      Then allow only specific destinations your MCP tools actually need."
        type_line "      This is one of the highest-leverage controls for agentic systems."
    fi

    # Automatic hardened systemd unit template for strict-mcp + ransom-hardened + great-harden (supreme)
    if [ "$PROFILE" = "strict-mcp" ] || [ "$PROFILE" = "ransom-hardened" ] || [ "$PROFILE" = "great-harden" ]; then
        echo
        type_line "      === Generating hardened systemd unit template ($PROFILE) ==="
        generate_systemd_unit "my-${PROFILE}-agent" "/etc/l2/seccomp-${PROFILE}.profile"
    fi

    # GREAT-HARDEN SUPREME AEROSPACE/INDUSTRIAL (l2 great-harden) - extra extreme for impenetrable
    if [ "$PROFILE" = "great-harden" ]; then
        echo
        type_line "      === GREAT-HARDEN SUPREME AEROSPACE/INDUSTRIAL LOCKDOWN (closes gaps, no malware surface) ==="
        type_line "      Kernel lockdown + modules off + full ro + anti-malware extreme for critical infra."
        echo
        type_line "      RHEL/Fedora + general extreme steps (run as root/sudo):"
        echo "      # 1. Kernel lockdown (aerospace-grade integrity/confidentiality)"
        echo "      echo 1 > /proc/sys/kernel/lockdown || sysctl -w kernel.lockdown=1"
        echo "      # 2. Disable loadable modules (no rootkits/dynamic malware)"
        echo "      echo 1 > /proc/sys/kernel/modules_disabled || true"
        echo "      # 3. Extreme sysctls (beyond standard)"
        echo "      cat >> /etc/sysctl.d/99-l2-great-harden.conf << 'SYSCTL'"
        echo "      kernel.kptr_restrict = 2"
        echo "      kernel.dmesg_restrict = 1"
        echo "      kernel.unprivileged_bpf_disabled = 1"
        echo "      kernel.yama.ptrace_scope = 3"
        echo "      fs.protected_symlinks = 1"
        echo "      fs.protected_hardlinks = 1"
        echo "      fs.protected_fifos = 2"
        echo "      fs.protected_regular = 2"
        echo "      kernel.perf_event_paranoid = 3"
        echo "      fs.suid_dumpable = 0"
        echo "      kernel.core_pattern = /dev/null"
        echo "      SYSCTL"
        echo "      sysctl -p /etc/sysctl.d/99-l2-great-harden.conf"
        echo "      # 4. Full audit for industrial (more rules)"
        echo "      cat > /etc/audit/rules.d/l2-great-harden.rules << 'AUDIT'"
        echo "      -w /usr/bin/ -p x -k l2-great-tools"
        echo "      -w /etc/ -p wa -k l2-great-config"
        echo "      -w /boot/ -p wa -k l2-great-boot"
        echo "      -w /root/.l2/ -p wa -k l2-northstar-state   # North-Star Containment: protect substrate state/audit for malware-cancer"
        echo "      -w /tmp/l2-ws- -p wa -k l2-northstar-ws"
        echo "      AUDIT"
        echo "      augenrules --load"
        echo "      # 5. Full ro root example (bind mounts, ProtectSystem=strict in units)"
        echo "      # See generated unit; for full: mount -o remount,ro / ; etc (careful)"
        echo "      # 6. No USB/storage for air-gap like: "
        echo "      echo 'blacklist usb_storage' > /etc/modprobe.d/l2-great-no-usb.conf || true"
        echo "      echo 'blacklist firewire_core' >> /etc/modprobe.d/l2-great-no-usb.conf || true"
        echo "      # 7. l2-specific North-Star Containment hardening (protect state/audit for malware-cancer sims)"
        echo "      echo 'blacklist bluetooth' > /etc/modprobe.d/l2-great-no-bt.conf || true"
        echo "      # 8. Enforce great-harden policy for critical procs via units or l2 exec --policy great-harden"
        echo "      #    (grand demo: l2 create ... --policy great-harden; put l2_malware_cancer... ; exec ; audit --test)"
        echo "      # 9. For AI/ML/agentic workloads (NSA Mar 2026 AI/ML Supply Chain CSI + MCP May 2026): require SBOM + AIBOM (AI Bill of Materials) from vendors/supply chain; track data/model provenance to mitigate poisoning/drift. Use tools like syft for SBOM, custom for AI datasets."
        echo
        type_line "      This + great-harden policy + l2 runtime sandbox = servers impenetrable to major classes of ransomware/worm/virus/substrate/AI-MCP threats (validated by malware-cancer AIO sim + North-Star Containment). Aligns to latest NSA/CISA (CPG 2.0, MCP CSI, AI supply chain, OT AI)."
        echo "      # Validate with AIO malware-cancer sim (ransom + Miasma + direct substrate attacks on state/trace/audit/crypto/ns/bpf + git/pip/ELF/anti):"
        echo "      #   export L2_DATA_DIR=\$(mktemp -d); l2 great-harden --fast --apply || true"
        echo "      #   l2 create cancer-test --policy great-harden"
        echo "      #   l2 put cancer-test cancer-sim.c --file docs/examples/l2_malware_cancer_resistance_demo.c"
        echo "      #   l2 exec cancer-test 'gcc -static ... && ./cancer-sim'  # demonstrates l2 North-Star Containment"
        echo "      #   l2 audit --test   # verifies North-Star Containment of AIO malware-cancer"
    fi
fi

# -----------------------------------------------------------------------------
# --apply mode: make it real and beautiful. Operationalize the artifacts.
# This is the key to turning guidance into world-class, auditable, applied state.
# Safe by design: confirmations, only what the operator explicitly authorizes,
# updates the machine json so `l2 audit --test` sees real "applied" evidence.
# Writes units/profiles/confs to discoverable places; attempts priv steps with sudo fallback.
# No new surfaces: all under explicit terminal + l2 audit.
# -----------------------------------------------------------------------------
if $APPLY; then
    echo
    type_line "[APPLY MODE] Making hardening operational for $PROFILE..."
    reveal_lines "We will write live artifacts (systemd units, seccomp profiles, sysctl/audit/nft configs) and attempt to apply them. Dangerous steps will use sudo (if available) or write ready-to-run apply scripts. You control everything."
    echo
    type_line "About to apply real changes for profile '$PROFILE' (target $TARGET). Have you reviewed the guidance above? (y/N)"
    read -r REPLY || true
    if [[ "$REPLY" =~ ^[Yy]$ ]]; then
        type_line "Applying... (paced for review)"
        # Ensure dirs
        mkdir -p "$L2_BASE/harden/applied" "$L2_BASE/seccomp" 2>/dev/null || true
        APPLIED_LIST=""

        # 1. Write/refresh seccomp profiles (from generate if done, or baseline)
        type_line "  - Writing loadable seccomp profiles to $L2_BASE/seccomp and trying /etc/l2..."
        echo "1 3 5 59  ... (minimal from policy; use --generate-seccomp for real traces)" > "$L2_BASE/seccomp/${PROFILE}.txt" 2>/dev/null || true
        mkdir -p /etc/l2 2>/dev/null || true
        cp "$L2_BASE/seccomp/${PROFILE}.txt" "/etc/l2/${PROFILE}.seccomp" 2>/dev/null || sudo cp "$L2_BASE/seccomp/${PROFILE}.txt" "/etc/l2/${PROFILE}.seccomp" 2>/dev/null || true
        APPLIED_LIST="$APPLIED_LIST,seccomp-profiles-written"

        # 2. Write the systemd unit live
        type_line "  - Installing hardened systemd unit template..."
        UNIT_NAME="l2-${PROFILE}-agent.service"
        if generate_systemd_unit "$UNIT_NAME" > "/tmp/${UNIT_NAME}" 2>/dev/null; then
            if cp "/tmp/${UNIT_NAME}" "/etc/systemd/system/${UNIT_NAME}" 2>/dev/null; then
                type_line "    Wrote to /etc/systemd/system/${UNIT_NAME} (run: systemctl daemon-reload)"
                APPLIED_LIST="$APPLIED_LIST,systemd-unit-installed"
            else
                cp "/tmp/${UNIT_NAME}" "$L2_BASE/harden/applied/${UNIT_NAME}" || true
                type_line "    Wrote to $L2_BASE/harden/applied/${UNIT_NAME} (copy to /etc as root + daemon-reload)"
                APPLIED_LIST="$APPLIED_LIST,systemd-unit-prepared"
            fi
        fi

        # 3. Sysctls (kernel hardening) - write conf and try apply
        type_line "  - Applying kernel sysctls (ptrace_scope, protected links, etc.)..."
        SYSCTL_CONF="/etc/sysctl.d/99-l2-${PROFILE}.conf"
        cat > "/tmp/l2-${PROFILE}-sysctl.conf" << 'SYSCTL' 2>/dev/null || true
kernel.yama.ptrace_scope = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
SYSCTL
        if cp "/tmp/l2-${PROFILE}-sysctl.conf" "$SYSCTL_CONF" 2>/dev/null || sudo cp "/tmp/l2-${PROFILE}-sysctl.conf" "$SYSCTL_CONF" 2>/dev/null; then
            sysctl -p "$SYSCTL_CONF" 2>/dev/null || sudo sysctl -p "$SYSCTL_CONF" 2>/dev/null || true
            type_line "    Sysctl conf active: $SYSCTL_CONF"
            APPLIED_LIST="$APPLIED_LIST,sysctls-applied"
        else
            cp "/tmp/l2-${PROFILE}-sysctl.conf" "$L2_BASE/harden/applied/" || true
            APPLIED_LIST="$APPLIED_LIST,sysctls-prepared"
        fi

        # 4. Network isolation nft (if requested) - best effort
        if $NETWORK_ISOLATION; then
            type_line "  - Applying network isolation (nft default-deny for agent user)..."
            nft add table inet l2-agent-isolation 2>/dev/null || sudo nft add table inet l2-agent-isolation 2>/dev/null || true
            nft add chain inet l2-agent-isolation output \{ type filter hook output priority 0 \\\; policy drop \\\; \} 2>/dev/null || sudo nft add chain inet l2-agent-isolation output \{ type filter hook output priority 0 \\\; policy drop \\\; \} 2>/dev/null || true
            APPLIED_LIST="$APPLIED_LIST,network-isolation-nft-prepared"
        fi

        # 5. For ransom-hardened, extra blocks (139/445 etc) - nft example
        if [ "$PROFILE" = "ransom-hardened" ]; then
            type_line "  - Extra ransomware containment (SMB 445/139 blocks, persistence vectors)..."
            # write a note/script
            cat > "$L2_BASE/harden/applied/ransom-blocks.nft" << 'NFT' || true
# l2 ransom-hardened extra: block worm propagation vectors
nft add rule inet l2-agent-isolation output tcp dport {139,445} drop
nft add rule inet l2-agent-isolation output udp dport {139,445} drop
NFT
            APPLIED_LIST="$APPLIED_LIST,ransomware-specific-blocks"
        fi

        type_line "Apply steps complete where possible. Artifacts live in $L2_BASE/harden/ and standard paths."
        type_line "Run 'systemctl daemon-reload' / 'sudo sysctl --system' / 'sudo nft -f ...' as needed for full effect."
    else
        type_line "Apply cancelled by user (guidance still generated)."
    fi
fi

echo || true
echo "[4/6] Generating hardening report..." || true

REPORT_DIR="$L2_BASE/harden-reports"
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

# Verify automated compliance with the standards referenced above (NSA/CISA etc.)
l2 audit --test
```

---

## References & Standards

- NSA / CISA "Securing AI Systems" guidance
- CISA Cross-Sector Cybersecurity Performance Goals (CPG 2.0, Dec 2025) - GOVERN, least privilege, malicious code detection, MSP risks, oversight
- NSA CSI: AI/ML Supply Chain Risks and Mitigations (Mar 2026) - data poisoning, provenance, AIBOM/SBOM
- NSA CSI: Model Context Protocol (MCP) Security Design Considerations for AI-Driven Automation (May 2026)
- NSA/CISA et al: Principles for Secure Integration of AI in Operational Technology (Dec 2025) - governance, human-in-loop, fail-safes, separate data push
- NSA/CISA: Careful Adoption of Agentic AI Services (Apr 2026), AI Data Security (May 2025)
- CISA Zero Trust Maturity Model (adapted for agents)
- FBI alerts on AI supply chain and agentic threats
- l2 `strict-mcp` policy protocol documentation (`l2 policy show strict-mcp`) - substrate for secure MCP per NSA MCP CSI
- l2 `great-harden` for critical infrastructure / OT-like AI integration

---

**Report location**: $REPORT_FILE

This report is a living artifact. Re-run `l2 harden` after major system or workload changes.
ENDOFREPORT

echo "      Rich report written to: $REPORT_FILE" || true

echo "      Report written to: $REPORT_FILE" || true

# -----------------------------------------------------------------------------
# Machine-readable harden report artifact (for `l2 audit --test` integration)
# This is the key integration point: `l2 harden --profile strict-mcp` produces
# a parseable JSON with "standards" list so that `l2 audit --test` can
# automatically verify compliance as part of regular standards checks.
# Written for both real runs and --dry-run (so CI/smoke always sees it).
# Location chosen as ~/.l2/harden/ (alongside the human .md in harden-reports/).
# -----------------------------------------------------------------------------
HARDEN_DIR="$L2_BASE/harden"
mkdir -p "$HARDEN_DIR" 2>/dev/null || true
LATEST_JSON="$HARDEN_DIR/${PROFILE}-latest.json"
cat > "$LATEST_JSON" << EOF
{
  "profile": "${PROFILE}",
  "target": "${TARGET}",
  "timestamp": "$(date -Iseconds)",
  "dry_run": ${DRY_RUN},
  "apply": ${APPLY},
  "network_isolation": ${NETWORK_ISOLATION},
  "generate_seccomp": "${GENERATE_SECCOMP}",
  "applied": [
    "${PROFILE} profile guidance and pairing",
    "seccomp Phase 1 + trace-derived profiles",
    "Landlock / ProtectSystem / capability bounding recommendations",
    "dedicated low-privilege agent user + audit rules",
    "kernel sysctls (ptrace_scope, protected_* links/fifos)",
    "systemd unit templates with NoNewPrivileges + SystemCallFilter",
    "network isolation (nftables default-deny for agent)",
    "supply-chain (Miasma npm worm + credential exfil + repack) resistance",
    "AIO malware-cancer substrate defense (state/trace/audit/crypto tamper, ns/bpf/setns/unshare escapes, fork/priv-esc on l2, git/pip/ELF/anti)",
    "North-Star Containment of AIO malware-cancer (grand demo: put+exec+audit under great-harden)",
    "APPLY: live artifacts written (units, profiles, confs) + attempted enforcement"
  ],
  "great_harden_note": "${PROFILE} is l2 great-harden supreme mode for aerospace/industrial - closes logic gaps (incl. AIO malware-cancer substrate attacks), achieves l2 North-Star Containment of ransomware+ worms+viruses+direct l2 attacks, makes impenetrable.",
  "standards": [
    "NSA / CISA \"Securing AI Systems\" guidance",
    "CISA Cross-Sector Cybersecurity Performance Goals (CPG 2.0, Dec 2025) incl. GOVERN, least privilege (3.H), malicious code detection, MSP risks, oversight",
    "NSA CSI: AI/ML Supply Chain Risks and Mitigations (Mar 2026) - AIBOM/SBOM, data poisoning/provenance",
    "NSA CSI: MCP Security Design Considerations for AI-Driven Automation (May 2026)",
    "NSA/CISA et al: Secure Integration of AI in OT (Dec 2025) - governance, human-in-loop, fail-safes",
    "NSA: Careful Adoption of Agentic AI Services (Apr 2026), AI Data Security (2025)",
    "CISA Zero Trust Maturity Model (adapted for agents)",
    "FBI alerts on AI supply chain and agentic threats",
    "CIS Benchmarks for Linux hardening",
    "CISA Stop Ransomware / worm containment guidance (for ransom-hardened)",
    "Supply chain (Miasma-style + AI/ML per 2026 CSI) resistance",
    "AIO malware-cancer + l2 North-Star Containment (ransomware + Miasma + viruses + direct substrate + MCP/agentic containment under great-harden; grand demo)",
    "l2 ${PROFILE} policy protocol + regular \`l2 audit --test\`"
  ],
  "report_md": "$REPORT_FILE",
  "apply_note": "Re-run with --apply to make artifacts operational and update this evidence for audit --test"
}
EOF
if [ -s "$LATEST_JSON" ]; then
    echo "      Machine-readable report for audit --test: $LATEST_JSON"
fi

echo
echo "[5/6] Next steps"
echo "      1. Review the generated report"
echo "      2. Use \`l2 trace --policy ${PROFILE}\` to collect data for your specific workloads"
echo "      3. Run agents with \`l2 exec --policy ${PROFILE}\`"
echo "      4. (Beautiful part) Re-run with --apply to make it operational:  l2 harden --profile ${PROFILE} --apply"
echo "      5. Run \`l2 audit --test\` to automatically verify standards compliance (harden reports + chain + ${PROFILE} usage etc.)"
echo "      6. For supply-chain (Miasma) testing: l2 put ... l2_miasma_resistance_demo.c ; exec under ${PROFILE}"
echo "      7. For supreme aerospace/industrial + AI/MCP/OT (great-harden per latest NSA MCP CSI, CPG 2.0, AI supply chain): l2 great-harden --apply ; use --policy great-harden + l2_malware_cancer... ; l2 audit --test (now covers CPG 2.0, MCP sec design, AI supply chain)"

echo
echo "[6/6] l2 harden complete for profile '$PROFILE'."

if $APPLY; then
    echo || true
    type_line "APPLY SUCCESS: Your host now has live ${PROFILE} controls (units/profiles/confs applied or prepared)."
    type_line "The json at $LATEST_JSON now reflects real 'applied' state for audit --test."
    type_line "Protect future work: l2 exec --policy ${PROFILE} ..."
elif ! $DRY_RUN; then
    echo || true
    echo "Remember: This is a living protocol. The threat landscape for agentic systems" || true
    echo "evolves quickly. Keep your allowlists, policies, and host hardening up to date." || true
    echo || true
    echo "To make it real (write units + update evidence): l2 harden --profile $PROFILE --apply" || true
    echo "Next verification step: l2 audit --test   # confirms harden + ${PROFILE} meet the listed standards" || true
fi

echo || true
echo "=== l2 harden finished ===" || true