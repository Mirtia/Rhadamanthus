#!/bin/bash

# Script to verify the newly added offsets for comprehensive module detection
# This script uses pahole to inspect kernel data structures and verify our offsets

echo "=== Verifying Newly Added Offsets for Comprehensive Module Detection ==="
echo ""

# Check if pahole is available
if ! command -v pahole &> /dev/null; then
    echo "Error: pahole is not installed. Please install it first:"
    echo "  Ubuntu/Debian: sudo apt install dwarves"
    echo "  RHEL/CentOS: sudo yum install dwarves"
    exit 1
fi

# Parse command line arguments
VMLINUX_PATH=""
if [ $# -eq 1 ]; then
    VMLINUX_PATH="$1"
    if [ ! -f "$VMLINUX_PATH" ]; then
        echo "Error: vmlinux file '$VMLINUX_PATH' not found!"
        exit 1
    fi
    echo "Using provided vmlinux: $VMLINUX_PATH"
else
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
            echo ""
            echo "Or provide a vmlinux file as argument:"
            echo "  $0 /path/to/vmlinux"
            exit 1
        fi
    fi
    echo "Using vmlinux: $VMLINUX_PATH"
fi

echo ""

# Check rb_node structure
echo "=== struct rb_node offsets ==="
pahole -C rb_node "$VMLINUX_PATH" 2>/dev/null || echo "rb_node not found in debug info"

echo ""
echo "=== struct kset offsets ==="
pahole -C kset "$VMLINUX_PATH" 2>/dev/null || echo "kset not found in debug info"

echo ""
echo "=== struct kobject offsets ==="
pahole -C kobject "$VMLINUX_PATH" 2>/dev/null || echo "kobject not found in debug info"

echo ""
echo "=== struct module_kobject offsets ==="
pahole -C module_kobject "$VMLINUX_PATH" 2>/dev/null || echo "module_kobject not found in debug info"

echo ""
echo "=== struct latch_tree_node offsets ==="
pahole -C latch_tree_node "$VMLINUX_PATH" 2>/dev/null || echo "latch_tree_node not found in debug info"

echo ""
echo "=== struct mod_tree_node offsets ==="
pahole -C mod_tree_node "$VMLINUX_PATH" 2>/dev/null || echo "mod_tree_node not found in debug info"

echo ""
echo "=== struct mod_tree offsets ==="
pahole -C mod_tree "$VMLINUX_PATH" 2>/dev/null || echo "mod_tree not found in debug info"

echo ""
echo "=== struct vmap_area offsets ==="
pahole -C vmap_area "$VMLINUX_PATH" 2>/dev/null || echo "vmap_area not found in debug info"

echo ""
echo "=== struct module (looking for bug_list) ==="
pahole -C module "$VMLINUX_PATH" 2>/dev/null | grep -A 5 -B 5 bug_list || echo "bug_list not found in module structure"

echo ""
echo "=== struct ftrace_mod_map offsets ==="
pahole -C ftrace_mod_map "$VMLINUX_PATH" 2>/dev/null || echo "ftrace_mod_map not found in debug info"

echo ""
echo "=== struct module (looking for taints) ==="
pahole -C module "$VMLINUX_PATH" 2>/dev/null | grep -A 5 -B 5 taints || echo "taints not found in module structure"

echo ""
echo "=== Alternative: Search for module-related structures ==="
pahole -l "$VMLINUX_PATH" 2>/dev/null | grep -i module | head -10

echo ""
echo "=== Alternative: Search for tree-related structures ==="
pahole -l "$VMLINUX_PATH" 2>/dev/null | grep -i tree | head -10

echo ""
echo "=== Alternative: Search for vmap structures ==="
pahole -l "$VMLINUX_PATH" 2>/dev/null | grep -i vmap | head -10

