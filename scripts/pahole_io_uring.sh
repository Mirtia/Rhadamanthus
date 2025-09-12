#!/usr/bin/bash
# Usage: ./inspect_uring.sh [vmlinux_path] [logfile_path]

DEFAULT_VMLINUX="${HOME}/vmlinux-5.15.0-139-generic"
DEFAULT_LOGFILE="uring_offsets.log"

VMLINUX=${1:-$DEFAULT_VMLINUX}
LOGFILE=${2:-$DEFAULT_LOGFILE}

touch "$LOGFILE"
{
  echo "Inspecting $VMLINUX at $(date)..."

  echo
  sudo pahole --hex -C io_ring_ctx,io_rings,io_kiocb,io_uring_task "$VMLINUX"

  echo
  echo "[*] Expanded nested members of io_ring_ctx"
  sudo pahole --hex -E -C io_ring_ctx "$VMLINUX"

  echo
  echo "[*] Cross-check with gdb type printer"
  gdb -q "$VMLINUX" \
    -ex 'set print type hex on' \
    -ex 'ptype /o struct io_ring_ctx' \
    -ex 'ptype /o struct io_uring_task' \
    -ex 'ptype /o struct io_kiocb' \
    -ex quit

  echo "Done $(date)..."
  echo
} >>"$LOGFILE" 2>&1
