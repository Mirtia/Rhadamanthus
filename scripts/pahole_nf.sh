# Script to verify netfilter structure offsets using pahole from a vmlinux file.

#!/bin/bash

echo "=== Netfilter Structure Offset Verification ==="
echo ""

# Check if pahole is available
if ! command -v pahole &> /dev/null; then
    echo "Error: pahole is not installed. Please install it first:"
    echo "  Ubuntu/Debian: sudo apt install dwarves"
    echo "  RHEL/CentOS: sudo yum install dwarves"
    exit 1
fi

KERNEL_VERSION="5.15.0-139-generic"
echo "Kernel version: $KERNEL_VERSION"
echo ""

# Check if vmlinux is available
VMLINUX_PATH="$HOME/vmlinux-$KERNEL_VERSION"
if [ ! -f "$VMLINUX_PATH" ]; then
    echo "Warning: $VMLINUX_PATH not found. Trying alternative paths..."
    VMLINUX_PATH="/usr/lib/debug/boot/vmlinux-$KERNEL_VERSION"
    if [ ! -f "$VMLINUX_PATH" ]; then
        echo "Error: vmlinux not found. Please install kernel debug symbols:"
        echo "  Ubuntu/Debian: sudo apt install linux-image-$KERNEL_VERSION-dbgsym"
        echo "  RHEL/CentOS: sudo yum install kernel-debuginfo"
        exit 1
    fi
fi

echo "Using vmlinux: $VMLINUX_PATH"
echo ""

# Extract netfilter-related structure offsets
echo "=== struct netns_nf offsets ==="
pahole -C netns_nf "$VMLINUX_PATH" 2>/dev/null || echo "netns_nf not found"

echo ""
echo "=== struct nf_hook_entries offsets ==="
pahole -C nf_hook_entries "$VMLINUX_PATH" 2>/dev/null || echo "nf_hook_entries not found"

echo ""
echo "=== struct nf_hook_entry offsets ==="
pahole -C nf_hook_entry "$VMLINUX_PATH" 2>/dev/null || echo "nf_hook_entry not found"

echo ""
echo "=== struct nf_hook_ops offsets ==="
pahole -C nf_hook_ops "$VMLINUX_PATH" 2>/dev/null || echo "nf_hook_ops not found"

echo ""
echo "=== struct net offsets ==="
pahole -C net "$VMLINUX_PATH" 2>/dev/null | head -20 || echo "net not found"

echo ""
echo "=== Alternative: Search for netfilter-related structures ==="
pahole -l "$VMLINUX_PATH" 2>/dev/null | grep -i netfilter | head -10

echo ""
echo "=== Alternative: Search for nf_hook structures ==="
pahole -l "$VMLINUX_PATH" 2>/dev/null | grep -i "nf_hook" | head -10

echo ""
echo "=== Alternative: Search for netns structures ==="
pahole -l "$VMLINUX_PATH" 2>/dev/null | grep -i "netns" | head -10
