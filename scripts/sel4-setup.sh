#!/bin/bash
# l2 sel4-setup - Full one-command seL4/Microkit developer environment bootstrap
# Invoked via: l2 sel4-setup
#
# This script sets up a ready-to-use workspace for building seL4/Micorkit systems
# that can host the l2 substrate (long-term: l2-core as a protection domain).

set -euo pipefail

WORKSPACE="$HOME/l2-sel4-workspace"
L2_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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

# 5. Microkit SDK + optional containerized seL4 environment
echo "[5/6] Getting Microkit toolchain (SDK first - recommended)..."
if command -v curl >/dev/null 2>&1; then
    SDK_URL="https://github.com/seL4/microkit/releases/download/2.2.0/microkit-sdk-2.2.0-linux-x86-64.tar.gz"
    if [ ! -f microkit-sdk-2.2.0.tar.gz ]; then
        echo "  Downloading official prebuilt Microkit SDK 2.2.0 (no container required)..."
        if curl -L -o microkit-sdk-2.2.0.tar.gz "$SDK_URL" 2>/dev/null; then
            echo "  ✓ Downloaded microkit-sdk-2.2.0.tar.gz"
            echo "    Extract with:  tar xzf microkit-sdk-2.2.0.tar.gz"
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

echo "  (Optional) Full seL4 dev container (if you need CAmkES, L4v, etc.):"
echo "    git clone https://github.com/seL4/seL4-CAmkES-L4v-dockerfiles.git"
echo "    cd seL4-CAmkES-L4v-dockerfiles"
echo "    # With podman (common on Fedora/RHEL):"
echo "    DOCKER=podman make user"
echo "    # Or with real docker:"
echo "    make user"
echo "  Then inside the container you can add the Microkit SDK above."

# 6. Emit a ready-to-use README in the workspace
echo "[6/6] Writing quickstart guide..."
cat > "$WORKSPACE/README-l2-sel4.md" << 'EOF'
# l2 + seL4 Workspace

This directory was created by `l2 sel4-setup`.

## What you have here
- `./l2-source`          → symlink to your l2 checkout (the CLI + core you are developing)
- `./microkit`           → (if present) shallow clone of https://github.com/seL4/microkit
- `microkit-sdk-*.tar.gz` → (if downloaded) official prebuilt Microkit SDK

## Recommended: Just use the official Microkit SDK (no Docker needed)

This is the simplest and most reliable path for Microkit development:

```bash
# From inside this workspace (or anywhere)
tar xzf microkit-sdk-2.2.0.tar.gz          # or the latest from the releases page
export MICROKIT_SDK=$(pwd)/microkit-sdk-2.2.0
# Now follow the official tutorial
# https://docs.sel4.systems/projects/microkit/tutorial/part0.html
```

The SDK is a self-contained tarball with everything you need (tool, libs, monitor, examples).

## Optional: Full seL4 development container

If you want the complete seL4 + CAmkES + L4v environment (heavier), use the
official Dockerfiles repo (works with both Docker and Podman):

```bash
git clone https://github.com/seL4/seL4-CAmkES-L4v-dockerfiles.git
cd seL4-CAmkES-L4v-dockerfiles

# Podman (very common on Fedora/RHEL systems that show "Emulate Docker CLI")
DOCKER=podman make user

# Real Docker
make user
```

This pulls the well-maintained `trustworthysystems/sel4` images from Docker Hub.

You can then drop the Microkit SDK tarball into a mounted directory and build
systems that will (in the future) be able to embed `l2-core`.

See also the Rust-focused demo containers:
  https://github.com/seL4/rust-microkit-demo (look in its `docker/` directory)

## Integration with l2 (current status)

- The `l2` CLI (`l2 sel4-setup`, `create`/`put`/`exec` etc.) works **today** on
  ordinary Linux using namespaces + basic Landlock (strict policy).
- The long-term goal is a true high-assurance backend where `l2-core` runs as
  a seL4/Microkit protection domain.
- See the plans:
    less l2-source/docs/PROTOTYPE_HARDENING_AND_SEL4_PLAN.md
    less l2-source/docs/SEL4_INTEGRATION.md

## Quick sanity check that your host l2 still works

```bash
(cd l2-source && cargo build --release && ./target/release/l2 status)
```

Happy high-assurance hacking.
EOF
echo "  ✓ Wrote $WORKSPACE/README-l2-sel4.md"

echo
echo "=== ✅ l2 sel4-setup complete ==="
echo
echo "Workspace ready: $WORKSPACE"
echo "Quickstart guide: cat $WORKSPACE/README-l2-sel4.md"
echo
echo "Most people should now just:"
echo "  tar xzf microkit-sdk-*.tar.gz"
echo "  and follow https://docs.sel4.systems/projects/microkit/tutorial/"
echo
echo "Run the host prototype from anywhere:"
echo "  cargo install --path $L2_DIR --force"
echo "  l2 --help"
echo "  l2 sel4-setup   # (idempotent)"
