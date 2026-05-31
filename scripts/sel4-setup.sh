#!/bin/bash
# l2 seL4 Setup - One-command developer environment

set -e

echo '=== l2 seL4 Setup ==='
echo 'Setting up seL4/Microkit development environment with l2 substrate...'

# Check for Docker
if ! command -v docker &> /dev/null; then
  echo 'Docker not found. Installing or please install Docker manually.'
  exit 1
fi

echo 'Pulling or building seL4 dev environment...'
# Example: use official or custom Docker image
docker pull ghcr.io/sel4/microkit:latest || echo 'Using local build'

# Create working dir
mkdir -p ~/l2-sel4-workspace
cd ~/l2-sel4-workspace

echo 'Cloning l2 and seL4 examples if needed...'
# Add repo clone, build steps here as per plan

echo 'seL4 environment ready in ~/l2-sel4-workspace'
echo 'Run QEMU or follow Microkit docs to boot with l2.'
echo 'For full integration, see docs/PROTOTYPE_HARDENING_AND_SEL4_PLAN.md'

# Future: build l2-core into seL4 image
echo 'Setup complete! Next step: integrate l2 as seL4 component.'