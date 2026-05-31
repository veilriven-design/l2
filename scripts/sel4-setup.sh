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
MISSING=""
for tool in git docker; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        MISSING="$MISSING $tool"
    fi
done
if [ -n "$MISSING" ]; then
    echo "  Warning: missing recommended tools:$MISSING"
    echo "  - Install docker for containerized seL4 builds (https://docs.docker.com/engine/install/)"
    echo "  - git is required to clone examples"
else
    echo "  ✓ git + docker present"
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

# 5. Docker seL4 environment (the real toolchain lives in container)
echo "[5/6] Preparing containerized seL4 dev environment..."
if command -v docker >/dev/null 2>&1; then
    echo "  Pulling seL4 Microkit development image (may take time on first run)..."
    if docker pull ghcr.io/sel4/microkit:latest 2>/dev/null; then
        echo "  ✓ Docker image ready: ghcr.io/sel4/microkit:latest"
        # Quick smoke: show the image has the expected entrypoint/tools
        docker run --rm ghcr.io/sel4/microkit:latest sh -c 'echo "  image contains: $(ls / 2>/dev/null | tr "\n" " "...)...; which make gcc 2>/dev/null || true"' || true
    else
        echo "  (Could not pull public image - you may need to build your own or use a corporate registry)"
        echo "  See docs/SEL4_INTEGRATION.md for custom image instructions."
    fi
else
    echo "  Docker not available - you will need it (or a native seL4 SDK) for actual kernel builds."
fi

# 6. Emit a ready-to-use README in the workspace
echo "[6/6] Writing quickstart guide..."
cat > "$WORKSPACE/README-l2-sel4.md" << 'EOF'
# l2 + seL4 Workspace

This directory was created by `l2 sel4-setup`.

## What you have
- ./l2-source  -> symlink to your l2 checkout (the CLI + core you are developing)
- ./microkit   -> (if cloned) the seL4 Microkit SDK + examples

## Next steps (prototype)
1. Read the integration plan:
   less l2-source/docs/PROTOTYPE_HARDENING_AND_SEL4_PLAN.md
   less l2-source/docs/SEL4_INTEGRATION.md

2. Typical flow with Docker + Microkit (example):
   docker run -it --rm \
     -v "$PWD:/work" \
     -w /work \
     ghcr.io/sel4/microkit:latest \
     bash

   Inside the container you can now build Microkit systems that will eventually
   embed l2-core (see core/ and host/ in l2-source).

3. Current status
   - l2 CLI (`l2 sel4-setup`, create/put/exec etc) works on Linux host today
     using namespaces + Landlock (strict policy).
   - The seL4 backend is the *target* for true high-assurance isolation.
   - l2-core (the narrow L2P protocol server) will become a Microkit PD.

4. Quick test that your host l2 is alive:
   (cd l2-source && cargo build --release && ./target/release/l2 status)

For the full vision see the docs in l2-source/docs/.

Happy high-assurance hacking.
EOF
echo "  ✓ Wrote $WORKSPACE/README-l2-sel4.md"

echo
echo "=== ✅ l2 sel4-setup complete ==="
echo
echo "Workspace ready: $WORKSPACE"
echo "Quickstart:      cat $WORKSPACE/README-l2-sel4.md"
echo
echo "Run the host prototype from anywhere:"
echo "  cargo install --path $L2_DIR --force"
echo "  l2 --help"
echo "  l2 sel4-setup   # (idempotent)"
echo
echo "Next (real seL4 work): follow the plan in l2-source/docs/*"
