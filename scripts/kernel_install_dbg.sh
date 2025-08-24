#!/usr/bin/bash
set -euo pipefail

# setup-kernel-dbgsym.sh
# Configure Ubuntu DDEBs and install kernel debug symbols for the running kernel.

want_proposed=0
if [[ "${1:-}" == "--enable-proposed" ]]; then
  want_proposed=1
fi

# Must be root.
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Run as root (use sudo)." >&2
  exit 1
fi

# Basic sanity: Ubuntu only.
if ! command -v lsb_release >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y lsb-release
fi

if ! grep -qi ubuntu /etc/os-release; then
  echo "ERROR: This script targets Ubuntu only." >&2
  exit 1
fi

CODENAME="$(lsb_release -cs)"
KREL="$(uname -r)"

echo "Detected Ubuntu codename: ${CODENAME}"
echo "Running kernel: ${KREL}"

DDEBS_FILE="/etc/apt/sources.list.d/ddebs.list"

echo "Configuring DDEBs in ${DDEBS_FILE} ..."
{
  echo "deb http://ddebs.ubuntu.com ${CODENAME} main restricted universe multiverse"
  echo "deb http://ddebs.ubuntu.com ${CODENAME}-updates main restricted universe multiverse"
  if [[ $want_proposed -eq 1 ]]; then
    echo "deb http://ddebs.ubuntu.com ${CODENAME}-proposed main restricted universe multiverse"
  fi
} > "${DDEBS_FILE}"

# Install keyring or fall back to legacy key import.
echo "Ensuring ubuntu-dbgsym keyring is installed ..."
set +e
apt-get update -y
apt-get install -y ubuntu-dbgsym-keyring
keyring_rc=$?
set -e

if [[ $keyring_rc -ne 0 ]]; then
  echo "Keyring package not available; importing key via keyserver (legacy) ..."
  apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C8CAB6595FDFF622
fi

echo "Refreshing APT indices ..."
apt-get update -y

# Determine candidate package name(s).
PKG1="linux-image-${KREL}-dbgsym"
PKG2="linux-image-${KREL}-generic-dbgsym"   # Some series publish this name instead

echo "Checking for candidate debug symbol packages:"
apt-cache policy "${PKG1}" "${PKG2}" || true

# Try to install whichever exists.
installed_pkg=""
if apt-cache policy "${PKG1}" | grep -q "Candidate:" && \
   ! apt-cache policy "${PKG1}" | grep -q "Candidate: (none)"; then
  echo "Installing ${PKG1} ..."
  apt-get install -y "${PKG1}"
  installed_pkg="${PKG1}"
elif apt-cache policy "${PKG2}" | grep -q "Candidate:" && \
     ! apt-cache policy "${PKG2}" | grep -q "Candidate: (none)"; then
  echo "Installing ${PKG2} ..."
  apt-get install -y "${PKG2}"
  installed_pkg="${PKG2}"
else
  echo "WARNING: No candidate dbgsym package visible for ${KREL}."
  echo "Attempting direct download via apt-get download (if available in current indices) ..."
  set +e
  apt-get download "linux-image-${KREL}-dbgsym"
  dl_rc=$?
  if [[ $dl_rc -ne 0 ]]; then
    apt-get download "linux-image-${KREL}-generic-dbgsym"
    dl_rc=$?
  fi
  set -e
  if [[ $dl_rc -eq 0 ]]; then
    echo "Installing downloaded .ddeb ..."
    dpkg -i linux-image-"${KREL}"*-dbgsym_*.ddeb || apt-get -f install -y
    installed_pkg="(downloaded .ddeb)"
  else
    echo "ERROR: Could not find or download dbgsym package for ${KREL} from configured pockets." >&2
    echo "Check that your kernel comes from ${CODENAME}-updates (or use --enable-proposed if on -proposed)." >&2
    exit 2
  fi
fi

# Verify presence and usability of vmlinux with debug info.
VMLINUX="/usr/lib/debug/boot/vmlinux-${KREL}"
echo "Verifying ${VMLINUX} ..."
if [[ -e "${VMLINUX}" ]]; then
  echo "OK: ${VMLINUX} exists."
  if command -v file >/dev/null 2>&1; then
    file "${VMLINUX}" | sed 's/^/file: /'
  fi
  echo "SUCCESS: Kernel debug symbols installed (${installed_pkg})."
else
  echo "ERROR: ${VMLINUX} not found after installation." >&2
  echo "Run: dpkg -L ${installed_pkg}  (if a package name) to inspect contents." >&2
  exit 3
fi
