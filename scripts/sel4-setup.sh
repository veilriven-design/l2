#!/bin/bash
# l2 sel4-setup - Full one-command seL4/Microkit developer environment bootstrap
# Invoked via: l2 sel4-setup
#
# This script sets up a ready-to-use workspace for building seL4/Micorkit systems
# that can host the l2 substrate (long-term: l2-core as a protection domain).
#
# v0.3.1: SDK tarball is the clear default/fast path for all users (including ancient
#         and low-RAM RHEL machines). The full CAmkES/L4v container now requires
#         explicit deliberate confirmation and carries strong time/hardware warnings.

set -euo pipefail

WORKSPACE="$HOME/l2-sel4-workspace"
L2_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# -----------------------------------------------------------------------------
# Spinner + live status for long-running commands (especially container setup)
# -----------------------------------------------------------------------------
run_with_spinner() {
    local description="$1"
    shift
    local cmd=("$@")

    local log_file
    log_file=$(mktemp /tmp/l2-setup-XXXXXX.log)

    # Run the real command in background, capturing all output
    "${cmd[@]}" >"$log_file" 2>&1 &
    local pid=$!

    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    local start
    start=$(date +%s)

    echo
    echo "$description"
    echo "  (This can take a long time on first run — pulling large container images)"
    echo

    while kill -0 "$pid" 2>/dev/null; do
        local now
        now=$(date +%s)
        local elapsed=$(( now - start ))
        local mins=$(( elapsed / 60 ))
        local secs=$(( elapsed % 60 ))

        # Grab the most recent non-empty line from the log for "live status"
        local status
        status=$(tail -n 30 "$log_file" | grep -v '^[[:space:]]*$' | tail -n 1 | cut -c1-85 || true)
        [ -z "$status" ] && status="starting up..."

        # Two-line updating status
        printf "\r\033[K  %s  Elapsed: %02dm %02ds\n" "${spin:i%10:1}" "$mins" "$secs"
        printf "\r\033[K  → %s" "$status"
        printf "\033[1A"   # cursor up so next iteration overwrites both lines

        sleep 0.15
        i=$(( i + 1 ))
    done

    wait "$pid"
    local exit_code=$?

    # Clear the two status lines cleanly
    printf "\r\033[K\n\r\033[K"
    printf "\033[1A\r\033[K"

    if [ $exit_code -eq 0 ]; then
        echo "  ✓ $description completed successfully."
    else
        echo "  ✗ $description failed (exit code $exit_code)."
        echo "    Last log lines:"
        tail -n 15 "$log_file" | sed 's/^/    /'
        echo
        echo "    Full log is at: $log_file"
    fi

    rm -f "$log_file"
    return $exit_code
}

echo "=== l2 sel4-setup ==="
echo "One-command seL4/Microkit + l2 development environment"
echo "Workspace: $WORKSPACE"
echo

# 1. Basic host tools check (non-fatal hints)
echo "[1/6] Checking host prerequisites..."
CONTAINER_CMD=""
if command -v podman >/dev/null 2>&1; then
    CONTAINER_CMD="podman"
elif command -v docker >/dev/null 2>&1; then
    CONTAINER_CMD="docker"
fi

if command -v git >/dev/null 2>&1; then
    echo "  ✓ git present"
else
    echo "  ! git not found (you can still download the Microkit SDK manually)"
fi

if [ -n "$CONTAINER_CMD" ]; then
    echo "  ✓ container tool present: $CONTAINER_CMD (optional for seL4 work)"
else
    echo "  ! No podman/docker found (perfectly fine — the official Microkit SDK needs none)"
fi

# 2. Create isolated workspace
echo "[2/6] Preparing workspace at $WORKSPACE"
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"

# 3. Record l2 source location for easy reference
echo "[3/6] Linking l2 source (current checkout at $L2_DIR)"
if [ ! -e l2-source ]; then
    ln -sfn "$L2_DIR" l2-source
fi
echo "  ✓ l2 source symlinked as ./l2-source"

# 4. Clone or update minimal seL4/Microkit example material (best effort)
echo "[4/6] Fetching seL4/Microkit examples (best effort, network optional)..."
if command -v git >/dev/null 2>&1; then
    if [ ! -d microkit ]; then
        # Official Microkit repo (contains examples, build system, docs)
        git clone --depth 1 https://github.com/seL4/microkit.git 2>/dev/null || echo "    (microkit clone skipped or failed - offline?)"
    else
        echo "    microkit/ already present"
    fi

    if [ -d microkit ] && [ ! -d microkit/example ]; then
        # Some releases have examples/ at top level of the tarball; repo structure differs slightly
        true
    fi
else
    echo "    git not found - skipping example clone"
fi

# 5. Microkit SDK (clear default / fast path) + optional heavy container
echo "[5/6] Getting Microkit toolchain (SDK is the recommended default for almost everyone)..."
if command -v curl >/dev/null 2>&1; then
    SDK_URL="https://github.com/seL4/microkit/releases/download/2.2.0/microkit-sdk-2.2.0-linux-x86-64.tar.gz"
    if [ ! -f microkit-sdk-2.2.0.tar.gz ]; then
        echo "  Downloading official prebuilt Microkit SDK 2.2.0 (no container required)..."
        if curl -L -o microkit-sdk-2.2.0.tar.gz "$SDK_URL" 2>/dev/null; then
            echo "  ✓ Downloaded microkit-sdk-2.2.0.tar.gz"
            echo "    This is the FAST, sufficient path for l2 + Microkit development."
            echo "    Extract with:  tar xzf microkit-sdk-2.2.0.tar.gz"
            echo "    export MICROKIT_SDK=\$(pwd)/microkit-sdk-2.2.0"
            echo "    Then follow:   https://docs.sel4.systems/projects/microkit/tutorial/part0.html"
        else
            echo "    (Download failed or offline - you can grab it manually later)"
        fi
    else
        echo "    SDK tarball already present"
    fi
else
    echo "    curl not found - skipping SDK download. Get it from:"
    echo "    https://github.com/seL4/microkit/releases"
fi

echo
echo "  (Optional, rarely needed) Full seL4/CAmkES/L4v dev container:"
echo "    Only use this if you specifically need the CAmkES modeling toolkit"
echo "    + the L4v/Isabelle verified stack. It is NOT required for l2/Microkit work."
echo "    The images are 10-50+ GB and first-time setup often takes many hours."

# 5b. Print distro-aware package hints (official tutorial is very Ubuntu-centric)
echo

echo "  Host packages needed to actually build/run examples from the tutorial:"

if [ -f /etc/os-release ]; then
    . /etc/os-release
fi

case "${ID:-unknown}" in
    fedora|rhel|centos|rocky|almalinux|ol )
        echo "    RHEL/Fedora-family (your system appears to be one):"
        echo "      sudo dnf install -y qemu-kvm qemu-img \\"
        echo "                          gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu make"
        echo "      sudo dnf group install -y \"Virtualization Host\"   # optional but helpful"
        echo "    Note: The aarch64 cross-compiler is often painful or missing"
        echo "    on RHEL 8-family systems. Container is the recommended path."
        ;;
    ubuntu|debian|pop )
        echo "    Debian/Ubuntu:"
        echo "      sudo apt update"
        echo "      sudo apt install -y make qemu-system-aarch64 gcc-aarch64-linux-gnu"
        ;;
    * )
        echo "    See the official 'Setting up your machine' section:"
        echo "      https://docs.sel4.systems/projects/microkit/tutorial/part0.html"
        ;;
esac

# 5c. On RHEL-family + podman: present the FULL container as a HEAVY, explicitly opt-in path only.
#     v0.3.1: SDK + host packages is the clear default. The container now requires deliberate confirmation
#     and carries realistic multi-hour (or multi-day on old hardware) warnings.
if [[ "${ID:-}" =~ ^(fedora|rhel|centos|rocky|almalinux|ol)$ ]] && [ "$CONTAINER_CMD" = "podman" ]; then
    echo
    echo ">>> RHEL-family system + podman detected."
    echo
    cat << 'HEAVY_WARN'
    The official seL4/CAmkES/L4v container (the thing 'make user' builds) is a HEAVY
    optional path. It is NOT required for l2 + Microkit work.

    What it actually does:
      - Pulls several large pre-built images (trustworthysystems/{sel4,camkes,l4v})
      - Runs the upstream Makefile which adds user-mapping layers on top
      - The L4v image alone carries a full Isabelle installation + proof sessions

    Realistic first-time wall time (the numbers the spinner will show):
      - Fast modern desktop / good SSD / 16+ GB RAM:   2–8 hours typical
      - 2015–2018 era hardware:                         8–20+ hours common
      - Ancient / low-spec machines (X200-class ThinkPads, early 2010s EliteBooks,
        mechanical HDDs, 4–8 GB RAM):                  15–40+ HOURS or more is normal.
        Rootless Podman on RHEL uses fuse-overlayfs; layer commits + extraction
        become I/O bound and memory pressure causes heavy swapping.

    Disk requirement: often 10–50+ GB once fully expanded.

    This path only makes sense if you specifically need the CAmkES modeling tools
    AND the L4v/Isabelle verified stack. For ordinary Microkit development
    (including eventually running l2-core as a protection domain) the SDK tarball
    you already have is the correct, fast tool.

    ALTERNATE / FAST ROUTE for older or low-RAM RHEL machines (recommended):
      sudo dnf install -y qemu-kvm qemu-img gcc-aarch64-linux-gnu \
                          binutils-aarch64-linux-gnu make
      cd ~/l2-sel4-workspace
      tar xzf microkit-sdk-2.2.0.tar.gz
      export MICROKIT_SDK=$(pwd)/microkit-sdk-2.2.0
      # then follow the official Microkit tutorial (excellent and self-contained)

HEAVY_WARN

    echo "    Only proceed with the full container if you have the time, disk space,"
    echo "    and a genuine need for CAmkES + L4v (most l2 users do not)."
    echo
    echo "    To continue anyway, you must type the exact phrase below."
    read -r -p "    Type exactly: yes i accept the long build time   --> " reply || true
    echo
    if [ "$reply" = "yes i accept the long build time" ]; then
        DOCKERFILES_DIR="$WORKSPACE/seL4-CAmkES-L4v-dockerfiles"
        if [ ! -d "$DOCKERFILES_DIR" ]; then
            echo "    Cloning official seL4 dockerfiles repo..."
            git clone --depth 1 https://github.com/seL4/seL4-CAmkES-L4v-dockerfiles.git "$DOCKERFILES_DIR" || {
                echo "    Clone failed. You can do it manually later."
            }
        fi

        if [ -d "$DOCKERFILES_DIR" ]; then
            echo "    Pre-pulling base images with fully-qualified names (prevents"
            echo "    'short-name resolution' TTY prompt from Podman on RHEL):"
            podman pull docker.io/trustworthysystems/camkes 2>&1 | tail -3 || true
            podman pull docker.io/trustworthysystems/sel4 2>&1 | tail -3 || true
            podman pull docker.io/trustworthysystems/l4v 2>&1 | tail -3 || true

            echo "    Command that will be run:"
            echo "      cd $DOCKERFILES_DIR && DOCKER=podman make user"
            echo
            echo "    (This step is deliberately slow on purpose on low-end hardware."
            echo "     You can safely Ctrl-C and finish with the SDK instead.)"
            echo

            if run_with_spinner "Setting up official seL4 development container" \
                    bash -c "cd '$DOCKERFILES_DIR' && DOCKER=podman make user"; then
                echo "    ✓ Container is ready. You can enter it later with:"
                echo "      cd $DOCKERFILES_DIR && DOCKER=podman make bash"
            else
                echo
                echo "    You can retry manually with (after the pre-pulls above):"
                echo "      cd $DOCKERFILES_DIR && DOCKER=podman make user"
            fi
        fi
    else
        echo "    Skipped (this is the correct default for the vast majority of users,"
        echo "    especially anyone on older or memory-constrained hardware)."
        echo
        echo "    If you later decide you truly need the full container you can still"
        echo "    run it manually:"
        echo "      cd $WORKSPACE/seL4-CAmkES-L4v-dockerfiles && DOCKER=podman make user"
    fi
fi

# 6. Emit a ready-to-use README in the workspace
echo "[6/6] Writing quickstart guide..."
cat > "$WORKSPACE/README-l2-sel4.md" << 'EOF'
# l2 on seL4 / Microkit Quickstart

This workspace was created by `l2 sel4-setup`.

## What you have here

- `./l2-source` → symlink to your current l2 checkout (live — edits are immediate)
- `./microkit` → shallow clone of the official Microkit repository (examples + build system)
- `microkit-sdk-2.2.0.tar.gz` → official prebuilt Microkit SDK 2.2.0 (**primary / fast path**)
- `seL4-CAmkES-L4v-dockerfiles/` → (RHEL + Podman, **opt-in only** since v0.3.1) sources for the full official container

## Primary Path (v0.3.1): Microkit SDK (no container required)

For l2 + Microkit development this is the correct, fast starting point on any hardware:

```bash
cd ~/l2-sel4-workspace
tar xzf microkit-sdk-2.2.0.tar.gz
export MICROKIT_SDK=$(pwd)/microkit-sdk-2.2.0

# Follow the official tutorial (excellent and self-contained)
# https://docs.sel4.systems/projects/microkit/tutorial/part0.html
```

The SDK contains the Microkit tool, libraries, monitor, and examples. It is the
simplest reliable way to start doing real seL4/Microkit development today.

On RHEL-family machines you will also want the host cross-compiler packages (see below).

## One-time RHEL / Podman Fix (only needed if you choose the full container later)

On RHEL, CentOS, Rocky, AlmaLinux, Fedora etc. with Podman, short-name resolution is
enforced. When `make user` (or the Makefile) runs non-interactively it fails with:

```
short-name resolution enforced but cannot prompt without a TTY
```

**Only do this if you have explicitly chosen the full container path** (see the
"Full seL4 + CAmkES/L4v Environment" section below — it is heavy and rarely needed).

```bash
cd ~/l2-sel4-workspace/seL4-CAmkES-L4v-dockerfiles

# Pre-pull using fully-qualified names
podman pull docker.io/trustworthysystems/camkes
podman pull docker.io/trustworthysystems/sel4
podman pull docker.io/trustworthysystems/l4v

# Then build the user container
DOCKER=podman make user
```

After this the container is ready and you can enter it with:

```bash
DOCKER=podman make bash
```

## Host Packages (RHEL / Fedora family) — fast path for older / low-RAM machines

```bash
sudo dnf install -y qemu-kvm qemu-img \
                    gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu make
sudo dnf group install -y "Virtualization Host"   # optional but helpful
```

These packages plus the SDK tarball above give you a working aarch64 cross
environment on RHEL without any giant container downloads or multi-hour builds.
This is the recommended route on low-RAM or pre-2015 hardware (X200-class machines, etc.).

## Full seL4 + CAmkES/L4v Environment (heavy, opt-in only since v0.3.1)

**Warning (added in v0.3.1):** The full official container is large (10-50+ GB) and
the first `make user` run is frequently a multi-hour (or multi-day on old hardware)
operation under rootless Podman.

Only use this path if you have a specific need for CAmkES modeling tools + the
L4v/Isabelle verified stack. It is **not** required for normal Microkit or l2 work.

On RHEL+podman, `l2 sel4-setup` will only start this after you type the exact
confirmation phrase `yes i accept the long build time`. Empty input or anything
else safely skips it.

If you later decide you need it:

```bash
cd ~/l2-sel4-workspace/seL4-CAmkES-L4v-dockerfiles
DOCKER=podman make user
```

Then to work inside it:

```bash
DOCKER=podman make bash     # drops you inside the container with everything
```

Inside the container your l2 tree is available at `/host` (and via the `l2-source`
symlink in the workspace root).

## Current l2 + seL4 Status

- The `l2` CLI and host prototype (Linux namespaces + Landlock) work today.
- `l2 sel4-setup` gives you a first-class, maintained on-ramp to a real seL4
  development environment (SDK + optional container).
- The actual port of l2-core to run as a Microkit protection domain is in
  progress. See the skeleton at `l2-source/l2.system` and the plans in
  `l2-source/docs/SEL4_INTEGRATION.md` and
  `l2-source/docs/PROTOTYPE_HARDENING_AND_SEL4_PLAN.md`.

Once the port advances you will build l2 systems using the Microkit SDK (or inside
the container) against the `l2.system` description and the l2_core ELF.

## Common Commands (from host)

```bash
# Re-run setup after pulling latest l2 changes (idempotent)
cargo install --path ~/l2 --force
l2 sel4-setup

# (Only if you previously accepted the heavy container and it finished)
cd ~/l2-sel4-workspace/seL4-CAmkES-L4v-dockerfiles
DOCKER=podman make bash

# Rebuild the container image from scratch (only if you chose the full path)
cd ~/l2-sel4-workspace/seL4-CAmkES-L4v-dockerfiles
DOCKER=podman make clean
DOCKER=podman make user
```

## Troubleshooting

**Podman short-name error**  
→ Run the three `podman pull docker.io/trustworthysystems/...` commands shown
in the "One-time RHEL / Podman Fix" section above.

**QEMU aarch64 or cross tools missing on host (SDK path)**  
→ Install the packages from the "Host Packages (RHEL / Fedora family) — fast path for older / low-RAM machines" section. This is the recommended route on vintage hardware.

**Container rebuild needed** (only if you are using the full path)  
```bash
DOCKER=podman make clean && DOCKER=podman make user
```

**"The container build is taking forever on my old machine" (v0.3.1+)**  
 This is expected. The full seL4/CAmkES/L4v images are huge and rootless Podman
layer operations on mechanical disks + limited RAM are extremely slow. Kill it
and use the SDK + host packages instead — you will be much happier.

**Want the latest l2 changes inside the container?**  
Just edit files in `~/l2` — the symlink and volume mount are live.

---

Generated by `l2 sel4-setup` (v0.3.1 — SDK-first with explicit opt-in for the heavy container)  
For project status see: `~/l2/STATUS.md` and the docs/ directory in l2-source.
EOF
echo "  ✓ Wrote $WORKSPACE/README-l2-sel4.md"

echo

echo "=== ✓ l2 sel4-setup complete ==="
echo
echo "Workspace ready: $WORKSPACE"
echo "Quickstart guide: cat $WORKSPACE/README-l2-sel4.md"
echo

if [[ "${ID:-}" =~ ^(fedora|rhel|centos|rocky|almalinux|ol)$ ]]; then
    echo "On your RHEL-family system (v0.3.1 behavior):"
    echo "  The Microkit SDK + host cross-compiler packages is the fast default path."
    echo "  Re-run 'l2 sel4-setup' after a 'git pull' if you want to be re-offered the"
    echo "  optional full container (it will again require the explicit confirmation phrase)."
    echo
    echo "  Only if you later need the full CAmkES/L4v stack:"
    echo "    cd $WORKSPACE/seL4-CAmkES-L4v-dockerfiles && DOCKER=podman make user"
else
    echo "Most people should now just:"
    echo "  tar xzf microkit-sdk-*.tar.gz"
    echo "  and follow https://docs.sel4.systems/projects/microkit/tutorial/"
fi

echo
echo "Run the host prototype from anywhere:"
echo "  cargo install --path $L2_DIR --force"
echo "  l2 --help"
echo "  l2 sel4-setup   # (idempotent, safe to re-run)"
