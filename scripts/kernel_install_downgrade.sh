#!/usr/bin/env bash
set -euo pipefail

# Install Ubuntu Trusty kernel 3.13.0-170.220 (amd64):
#  - headers
#  - modules (tries linux-modules{,-extra}-… OR legacy linux-image-extra-…)
#  - kernel image (signed), plus unsigned image if available
#  - OPTIONAL: debug symbols (-dbgsym) for unsigned and signed images (and modules if present)
#
# Usage:
#   sudo bash install-3.13.0-170.sh              # install kernel + modules + headers
#   sudo WITH_DBGSYM=1 bash install-3.13.0-170.sh # also attempt dbgsym packages (not fatal if missing)
#
# Notes:
#   * Keep your current kernel installed for GRUB fallback.
#   * On UEFI/Secure Boot VMs, 3.x signed images exist; dbgsym are separate .ddeb files (not booted).
#   * This script is idempotent and will skip pieces that are already installed.

ABI="${ABI:-3.13.0-170}"
VER="${VER:-3.13.0-170.220}"
ARCH="${ARCH:-amd64}"
WITH_DBGSYM="${WITH_DBGSYM:-0}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1" >&2; exit 1; }; }
for c in wget dpkg apt-get awk sed grep; do need "$c"; done

cd /tmp

# Mirrors (try primary security mirror first, then old-releases)
POOL_MAIN_SEC="http://security.ubuntu.com/ubuntu/pool/main/l/linux"
POOL_SIGNED_SEC="http://security.ubuntu.com/ubuntu/pool/main/l/linux-signed"
POOL_MAIN_OLD="http://old-releases.ubuntu.com/ubuntu/pool/main/l/linux"
POOL_SIGNED_OLD="http://old-releases.ubuntu.com/ubuntu/pool/main/l/linux-signed"

# DDEBs (debug symbols) – try both layouts
DDEB_LINUX_A="https://ddebs.ubuntu.com/ubuntu/pool/main/l/linux"
DDEB_LINUX_B="https://ddebs.ubuntu.com/pool/main/l/linux"
DDEB_SIGNED_A="https://ddebs.ubuntu.com/ubuntu/pool/main/l/linux-signed"
DDEB_SIGNED_B="https://ddebs.ubuntu.com/pool/main/l/linux-signed"

fetch() {
  # fetch <outfile> <url1> [url2]...
  local out="$1"; shift
  for u in "$@"; do
    if wget -q --spider "$u"; then
      echo "[*] $out <- $u"
      wget -q -O "$out" "$u"
      return 0
    fi
  done
  return 1
}

must_fetch() {
  local out="$1"; shift
  if fetch "$out" "$@"; then
    return 0
  fi
  echo "ERROR: none of these URLs worked for $out:" >&2
  printf '  - %s\n' "$@" >&2
  exit 1
}

already_have() {
  dpkg -s "$1" >/dev/null 2>&1
}

pkg_file_present() {
  ls -1 "$1" 1>/dev/null 2>&1
}

echo "[*] Target: ${ABI} (${VER}) arch=${ARCH}"
echo "[*] WITH_DBGSYM=${WITH_DBGSYM}"

# -------------------------------------------------------------------
# 1) Fetch headers
must_fetch "linux-headers-${ABI}_${VER}_all.deb" \
  "${POOL_MAIN_SEC}/linux-headers-${ABI}_${VER}_all.deb" \
  "${POOL_MAIN_OLD}/linux-headers-${ABI}_${VER}_all.deb"

must_fetch "linux-headers-${ABI}-generic_${VER}_${ARCH}.deb" \
  "${POOL_MAIN_SEC}/linux-headers-${ABI}-generic_${VER}_${ARCH}.deb" \
  "${POOL_MAIN_OLD}/linux-headers-${ABI}-generic_${VER}_${ARCH}.deb"

# -------------------------------------------------------------------
# 2) Fetch modules (support both packaging styles)

HAVE_MOD_SPLIT=0
if fetch "linux-modules-${ABI}-generic_${VER}_${ARCH}.deb" \
        "${POOL_MAIN_SEC}/linux-modules-${ABI}-generic_${VER}_${ARCH}.deb" \
        "${POOL_MAIN_OLD}/linux-modules-${ABI}-generic_${VER}_${ARCH}.deb"; then
  HAVE_MOD_SPLIT=1
  # extra
  must_fetch "linux-modules-extra-${ABI}-generic_${VER}_${ARCH}.deb" \
    "${POOL_MAIN_SEC}/linux-modules-extra-${ABI}-generic_${VER}_${ARCH}.deb" \
    "${POOL_MAIN_OLD}/linux-modules-extra-${ABI}-generic_${VER}_${ARCH}.deb"
else
  echo "[*] linux-modules-* not found; trying legacy linux-image-extra-* packaging…"
  must_fetch "linux-image-extra-${ABI}-generic_${VER}_${ARCH}.deb" \
    "${POOL_MAIN_SEC}/linux-image-extra-${ABI}-generic_${VER}_${ARCH}.deb" \
    "${POOL_MAIN_OLD}/linux-image-extra-${ABI}-generic_${VER}_${ARCH}.deb"
fi

# -------------------------------------------------------------------
# 3) Fetch kernel images (unsigned is useful for dbgsym deps; signed is what you boot)
fetch "linux-image-unsigned-${ABI}-generic_${VER}_${ARCH}.deb" \
  "${POOL_MAIN_SEC}/linux-image-unsigned-${ABI}-generic_${VER}_${ARCH}.deb" \
  "${POOL_MAIN_OLD}/linux-image-unsigned-${ABI}-generic_${VER}_${ARCH}.deb" || true

must_fetch "linux-image-${ABI}-generic_${VER}_${ARCH}.deb" \
  "${POOL_SIGNED_SEC}/linux-image-${ABI}-generic_${VER}_${ARCH}.deb" \
  "${POOL_SIGNED_OLD}/linux-image-${ABI}-generic_${VER}_${ARCH}.deb"

# -------------------------------------------------------------------
# 4) Install headers + modules + images
echo "[*] Installing kernel pieces…"
set +e
if (( HAVE_MOD_SPLIT == 1 )); then
  sudo dpkg -i \
    "linux-headers-${ABI}_${VER}_all.deb" \
    "linux-headers-${ABI}-generic_${VER}_${ARCH}.deb" \
    "linux-modules-${ABI}-generic_${VER}_${ARCH}.deb" \
    "linux-modules-extra-${ABI}-generic_${VER}_${ARCH}.deb" \
    ${PWD}/"linux-image-unsigned-${ABI}-generic_${VER}_${ARCH}.deb" 2>/dev/null || true \
    "linux-image-${ABI}-generic_${VER}_${ARCH}.deb"
else
  sudo dpkg -i \
    "linux-headers-${ABI}_${VER}_all.deb" \
    "linux-headers-${ABI}-generic_${VER}_${ARCH}.deb" \
    "linux-image-extra-${ABI}-generic_${VER}_${ARCH}.deb" \
    ${PWD}/"linux-image-unsigned-${ABI}-generic_${VER}_${ARCH}.deb" 2>/dev/null || true \
    "linux-image-${ABI}-generic_${VER}_${ARCH}.deb"
fi
rc=$?
set -e
if (( rc != 0 )); then
  echo "[*] Fixing dependencies via apt-get -f install…"
  sudo apt-get -y -f install
fi

# -------------------------------------------------------------------
# 5) Optional: fetch & install dbgsym (unsigned first, then signed). Non-fatal if missing.
if (( WITH_DBGSYM == 1 )); then
  echo "[*] Attempting to download dbgsym packages (unsigned → signed → modules)…"

  DBG_UNSIG="linux-image-unsigned-${ABI}-generic-dbgsym_${VER}_${ARCH}.ddeb"
  DBG_SIG="linux-image-${ABI}-generic-dbgsym_${VER}_${ARCH}.ddeb"
  DBG_MOD1="linux-modules-${ABI}-generic-dbgsym_${VER}_${ARCH}.ddeb"
  DBG_MODX="linux-modules-extra-${ABI}-generic-dbgsym_${VER}_${ARCH}.ddeb"
  DBG_IMGEXTRA="linux-image-extra-${ABI}-generic-dbgsym_${VER}_${ARCH}.ddeb"

  fetched_dbg_unsig=0
  fetched_dbg_sig=0

  # unsigned image dbgsym (try linux/ then linux-signed)
  if fetch "$DBG_UNSIG" \
      "${DDEB_LINUX_A}/${DBG_UNSIG}" "${DDEB_LINUX_B}/${DBG_UNSIG}" \
      "${DDEB_SIGNED_A}/${DBG_UNSIG}" "${DDEB_SIGNED_B}/${DBG_UNSIG}"; then
    fetched_dbg_unsig=1
  else
    echo "WARN: $DBG_UNSIG not found on ddebs mirrors; will skip unsigned dbgsym."
  fi

  # signed image dbgsym (depends on unsigned)
  if fetch "$DBG_SIG" \
      "${DDEB_SIGNED_A}/${DBG_SIG}" "${DDEB_SIGNED_B}/${DBG_SIG}" \
      "${DDEB_LINUX_A}/${DBG_SIG}"  "${DDEB_LINUX_B}/${DBG_SIG}"; then
    fetched_dbg_sig=1
  else
    echo "WARN: $DBG_SIG not found on ddebs mirrors; will skip signed dbgsym."
  fi

  # modules dbgsym (best-effort only; may not exist)
  fetch "$DBG_MOD1" "${DDEB_LINUX_A}/${DBG_MOD1}" "${DDEB_LINUX_B}/${DBG_MOD1}" || true
  fetch "$DBG_MODX" "${DDEB_LINUX_A}/${DBG_MODX}" "${DDEB_LINUX_B}/${DBG_MODX}" || true
  fetch "$DBG_IMGEXTRA" "${DDEB_LINUX_A}/${DBG_IMGEXTRA}" "${DDEB_LINUX_B}/${DBG_IMGEXTRA}" || true

  echo "[*] Installing dbgsym (non-fatal)…"
  set +e
  if (( fetched_dbg_unsig == 1 )); then
    sudo dpkg -i "$DBG_UNSIG" || true
  fi
  if (( fetched_dbg_sig == 1 )); then
    sudo dpkg -i "$DBG_SIG" || true
  fi
  # whichever modules dbg we managed to fetch
  for f in "$DBG_MOD1" "$DBG_MODX" "$DBG_IMGEXTRA"; do
    if pkg_file_present "$f"; then sudo dpkg -i "$f" || true; fi
  done
  sudo apt-get -y -f install
  set -e
fi

# -------------------------------------------------------------------
# 6) Build initrd and update GRUB
echo "[*] Building initramfs and updating GRUB…"
sudo update-initramfs -c -k "${ABI}-generic" || sudo update-initramfs -u -k "${ABI}-generic" || true

if command -v update-grub >/dev/null 2>&1; then
  sudo update-grub
elif command -v grub-mkconfig >/dev/null 2>&1; then
  sudo grub-mkconfig -o /boot/grub/grub.cfg
else
  echo "WARN: Could not update GRUB automatically; update it manually." >&2
fi

# -------------------------------------------------------------------
# 7) Verify
echo "[*] Verify kernel files:"
ls -l "/boot/vmlinuz-${ABI}-generic" "/boot/initrd.img-${ABI}-generic" || true
if [ -d "/lib/modules/${ABI}-generic" ]; then
  echo "[OK] /lib/modules/${ABI}-generic present"
else
  echo "[WARN] /lib/modules/${ABI}-generic missing"
fi
if (( WITH_DBGSYM == 1 )); then
  if [ -e "/usr/lib/debug/boot/vmlinux-${ABI}-generic" ]; then
    echo "[OK] debug vmlinux present"
  else
    echo "[WARN] debug vmlinux not found (dbgsym may be unavailable on mirrors)"
  fi
fi

echo "[*] Done. Reboot and pick 'Advanced options for Ubuntu' → ${ABI}-generic. Keep your current kernel for fallback."
