#!/bin/bash
set -e

# Minimal, flag-driven setup. Run with sudo for system-wide installs.
# Examples:
#   sudo bash setup-min.sh --basics --net --bpf --uv --liburing --go
#   sudo bash setup-min.sh --basics
#
# Flags (all optional):
#   --basics     build-essential, git, headers, python, etc.
#   --net        iproute2, ping, netcat, tcpdump
#   --bpf        bpftrace, bpftool, bpfcc-tools (+ libbpf-dev)
#   --uv         install Astral uv for current user
#   --liburing   build & install liburing + io_uring-cp
#   --go         install Go (default 1.22.6). Override: GO_VERSION=1.23.1 bash setup-min.sh --go

ENABLE_BASICS=0
ENABLE_NET=0
ENABLE_BPF=0
ENABLE_UV=0
ENABLE_LIBURING=0
ENABLE_GO=0
ENABLE_REPSITORIES=0

for arg in "$@"; do
  case "$arg" in
    --basics)   ENABLE_BASICS=1 ;;
    --net)      ENABLE_NET=1 ;;
    --bpf)      ENABLE_BPF=1 ;;
    --uv)       ENABLE_UV=1 ;;
    --liburing) ENABLE_LIBURING=1 ;;
    --go)       ENABLE_GO=1 ;;
    --repositories) ENABLE_REPSITORIES=1 ;;
    -h|--help)
      grep '^# ' "$0" | sed 's/^# //'
      exit 0
      ;;
  esac
done

apt_update_once() {
  if [ -z "${APT_UPDATED:-}" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    APT_UPDATED=1
  fi
}

apt_install() {
  apt_update_once
  apt-get install -y --no-install-recommends "$@"
}

if [ "$ENABLE_BASICS" -eq 1 ]; then
  apt_install \
    build-essential git pkg-config cmake \
    curl wget ca-certificates unzip tar xz-utils \
    python3 python3-venv python3-pip \
    "linux-headers-$(uname -r)"
fi

if [ "$ENABLE_NET" -eq 1 ]; then
  apt_install iproute2 iputils-ping dnsutils netcat-openbsd tcpdump
fi

if [ "$ENABLE_BPF" -eq 1 ]; then
  # Try apt first; if bpftool is missing, try to build from source (still minimal).
  apt_install bpftrace bpftool || true
  apt_install bpfcc-tools libbpf-dev libelf-dev zlib1g-dev || true

  if ! command -v bpftool >/dev/null 2>&1; then
    apt_install clang llvm libcap-dev flex bison libssl-dev libzstd-dev
    mkdir -p /usr/local/src
    if [ ! -d /usr/local/src/bpftool ]; then
      git clone --recurse-submodules https://github.com/libbpf/bpftool.git /usr/local/src/bpftool
    else
      git -C /usr/local/src/bpftool pull --ff-only
    fi
    make -C /usr/local/src/bpftool/src -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
    make -C /usr/local/src/bpftool/src install
  fi
fi

if [ "$ENABLE_UV" -eq 1 ]; then
  # Install to invoking user's $HOME. If run with sudo, prefer the original user.
  TARGET_HOME="${SUDO_USER:+/home/$SUDO_USER}"
  TARGET_HOME="${TARGET_HOME:-$HOME}"
  su - "${SUDO_USER:-$USER}" -c 'curl -fsSL https://astral.sh/uv/install.sh | sh'
  echo "Ensure $TARGET_HOME/.local/bin is in PATH"
fi

if [ "$ENABLE_LIBURING" -eq 1 ]; then
  apt_install libssl-dev
  mkdir -p /usr/local/src
  if [ ! -d /usr/local/src/liburing ]; then
    git clone https://github.com/axboe/liburing.git /usr/local/src/liburing
  else
    git -C /usr/local/src/liburing pull --ff-only
  fi
  make -C /usr/local/src/liburing -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
  make -C /usr/local/src/liburing install

  if [ -x /usr/local/src/liburing/examples/io_uring-cp ]; then
    install -m 0755 /usr/local/src/liburing/examples/io_uring-cp /usr/local/bin/io_uring-cp
  fi
fi

if [ "$ENABLE_GO" -eq 1 ]; then
  GO_VERSION="${GO_VERSION:-1.22.6}"
  GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
  URL="https://go.dev/dl/${GO_TAR}"
  rm -rf /usr/local/go
  curl -fsSL "$URL" -o "/tmp/${GO_TAR}"
  tar -C /usr/local -xzf "/tmp/${GO_TAR}"
  rm -f "/tmp/${GO_TAR}"
  if ! grep -q "/usr/local/go/bin" /etc/profile 2>/dev/null; then
    echo 'export PATH=/usr/local/go/bin:$PATH' >/etc/profile.d/go-path.sh
  fi
  echo "Go ${GO_VERSION} installed. If needed: export PATH=/usr/local/go/bin:\$PATH"
fi

if [ "$ENABLE_REPSITORIES" -eq 1 ]; then
  cd ~/Documents
  git clone https://github.com/Mirtia/Clueless-Admin.git
  git clone https://github.com/Mirtia/Rootkit-Suite.git
fi


echo "Done."
