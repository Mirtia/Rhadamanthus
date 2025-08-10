#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage: sudo ./get_vmlinux.sh <mapper-base> <dest-dir> [mountpoint]

  mapper-base : base /dev/mapper device (e.g. /dev/mapper/vg-ubuntu--20--04)
  dest-dir    : directory on the host where vmlinux will be copied
  mountpoint  : optional mount root (default: /mnt/vmi-<basename>)

Notes:
- This script will mount:
    <mapper-base>-part5 -> <mountpoint>          (root filesystem)
    <mapper-base>-part1 -> <mountpoint>/boot/efi (EFI, optional)
- It prefers debug vmlinux at <mountpoint>/usr/lib/debug/boot/vmlinux-*
- If missing, it will try extracting from <mountpoint>/boot/vmlinuz-*
  using 'extract-vmlinux' if present on the host.
USAGE
}

die() { echo "ERROR: $*" >&2; exit 1; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Run as root (sudo)."
  fi
}

main() {
  [[ $# -lt 2 || $# -gt 3 ]] && usage && exit 2
  need_root

  local base="$1"
  local dest="$2"
  local mnt="${3:-/mnt/vmi-$(basename "$base")}"
  local part_root="${base}-part5"
  local part_efi="${base}-part1"

  [[ -b "$base" || -e "$base" ]] || die "Base mapper device not found: $base"
  mkdir -p "$dest"

  # Show partition table for visibility
  echo "==> fdisk -l $base"
  fdisk -l "$base" || true

  # Prepare mountpoints
  mkdir -p "$mnt"
  trap 'echo "==> unmounting..."; umount -R "$mnt" 2>/dev/null || true; rmdir "$mnt" 2>/dev/null || true' EXIT

  echo "==> mounting root: $part_root -> $mnt (read-only)"
  mount -o ro "$part_root" "$mnt" || die "Failed to mount $part_root on $mnt"

  # Mount EFI if present (optional)
  if [[ -e "$part_efi" ]]; then
    mkdir -p "$mnt/boot/efi"
    if mount -o ro "$part_efi" "$mnt/boot/efi"; then
      echo "==> mounted EFI: $part_efi -> $mnt/boot/efi"
    else
      echo "==> warning: could not mount EFI partition $part_efi (continuing)"
    fi
  fi

  # 1) Prefer debug vmlinux within the guest root
  echo "==> searching for debug vmlinux under $mnt/usr/lib/debug/boot/"
  shopt -s nullglob
  local candidates_debug=("$mnt"/usr/lib/debug/boot/vmlinux-*)
  shopt -u nullglob

  if (( ${#candidates_debug[@]} > 0 )); then
    # Pick the newest (lexicographically last)
    IFS=$'\n' candidates_debug=($(printf '%s\n' "${candidates_debug[@]}" | sort))
    local src="${candidates_debug[-1]}"
    local out="$dest/$(basename "$src")"
    echo "==> found debug vmlinux: $src"
    cp -f --reflink=auto "$src" "$out"
    echo "==> copied to: $out"
    echo "==> done."
    return 0
  fi

  # 2) Fallback: try extracting from vmlinuz using extract-vmlinux if available
  echo "==> debug vmlinux not found. Trying to extract from vmlinuz…"
  shopt -s nullglob
  local candidates_z=("$mnt"/boot/vmlinuz-*)
  shopt -u nullglob
  if (( ${#candidates_z[@]} == 0 )); then
    die "No /boot/vmlinuz-* found inside the mounted filesystem."
  fi

  IFS=$'\n' candidates_z=($(printf '%s\n' "${candidates_z[@]}" | sort))
  local zsrc="${candidates_z[-1]}"
  local ver="$(basename "$zsrc" | sed -e 's/^vmlinuz-//')"
  local out2="$dest/vmlinux-$ver"

  if command -v extract-vmlinux >/dev/null 2>&1; then
    echo "==> using host's extract-vmlinux on: $zsrc"
    # Use -- to protect paths with spaces (unlikely here, but safe)
    if extract-vmlinux -- "$zsrc" > "$out2" 2>/dev/null; then
      echo "==> extracted vmlinux: $out2"
      echo "==> done."
      return 0
    else
      echo "==> extract-vmlinux failed; file may use an unexpected format."
    fi
  else
    echo "==> extract-vmlinux not found on host."
  fi

  # 3) Last-ditch attempt: try common decompressors directly (may fail)
  echo "==> attempting naive decompression (may fail)…"
  if file -b "$zsrc" | grep -qi 'gzip'; then
    zcat -- "$zsrc" > "$out2" || true
  elif file -b "$zsrc" | grep -qi 'xz'; then
    xzcat -- "$zsrc" > "$out2" || true
  elif file -b "$zsrc" | grep -qi 'bzip2'; then
    bzcat -- "$zsrc" > "$out2" || true
  elif file -b "$zsrc" | grep -qi 'lz4'; then
    lz4 -d --stdout -- "$zsrc" > "$out2" || true
  elif file -b "$zsrc" | grep -qi 'zstd'; then
    zstd -d -c -- "$zsrc" > "$out2" || true
  fi

  if [[ -s "$out2" ]]; then
    echo "==> produced: $out2 (verify it’s an ELF vmlinux: file \"$out2\")"
    echo "==> done."
    return 0
  fi

  die "Could not obtain a valid vmlinux. Install debug symbols in the guest (vmlinux under /usr/lib/debug/boot) or install 'extract-vmlinux' on the host."
}

main "$@"
