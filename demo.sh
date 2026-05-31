#!/bin/bash
# l2 Demo Script
# Run this to walk through the main capabilities of l2

set -e

DATA_DIR="/tmp/l2-demo-$$"
export L2_DATA_DIR="$DATA_DIR"

cleanup() {
    echo
    echo "Cleaning up demo data..."
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT

echo "========================================"
echo "l2 Demo - Host Prototype"
echo "========================================"
echo

echo "Data directory: $L2_DATA_DIR"
echo

echo ">>> 1. Check status"
./target/release/l2 status
echo

echo ">>> 2. Create an isolated system"
./target/release/l2 create review-bot
echo

echo ">>> 3. Put code and data into the system"
./target/release/l2 put review-bot main.rs --type code --content 'fn main() {
    println!("Hello from inside the l2 substrate!");
    println!("Only this isolated system can see this code.");
}'
./target/release/l2 put review-bot prompt.txt --content "Please review this code for security issues."
echo

echo ">>> 4. List what is inside the system"
./target/release/l2 list review-bot
echo

echo ">>> 5. Execute work inside the isolated system"
./target/release/l2 exec review-bot 'echo "Running arbitrary shell commands inside the container..."'
./target/release/l2 exec review-bot 'cat prompt.txt'
echo

echo ">>> 6. Retrieve an object back out"
./target/release/l2 get review-bot main.rs
echo

echo ">>> 7. JSON output (useful for tools/scripts)"
./target/release/l2 --json list review-bot
echo

echo ">>> 8. Strict policy demo (shows sandbox activation)"
./target/release/l2 create secure-agent --policy strict
./target/release/l2 put secure-agent secret.txt --content "This data should only be visible inside the strict system"
./target/release/l2 list secure-agent
./target/release/l2 exec secure-agent 'echo "Sandbox was applied above ^^^"'
./target/release/l2 destroy secure-agent
echo

echo ">>> 9. Clean up"
./target/release/l2 destroy review-bot
echo

echo "========================================"
echo "Demo complete!"
echo

echo "For the seL4 development path, run:"
echo "    ./target/release/l2 sel4-setup"
echo

echo "Then read the guide it creates:"
echo "    cat ~/l2-sel4-workspace/README-l2-sel4.md"
echo "========================================"