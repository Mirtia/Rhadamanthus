#!/bin/bash
set -e

# Examples:
#   sudo ./install-essentials.sh --basics --net --bpf --uv --liburing --go
#
# Flags (all optional):
#   --basics     build-essential, git, headers, python, etc.
#   --net        iproute2, ping, netcat, tcpdump
#   --bpf        bpftrace, bpftool, bpfcc-tools (+ libbpf-dev)
#   --uv         install Astral uv for current user
#   --liburing   build & install liburing + io_uring-cp
#   --go         install Go (default 1.22.6). Override: GO_VERSION=1.23.1 bash setup-min.sh --go
#   --clang14    install clang-14 from apt.llvm.org

ENABLE_BASICS=0
ENABLE_NET=0
ENABLE_BPF=0
ENABLE_UV=0
ENABLE_LIBURING=0
ENABLE_GO=0
ENABLE_CLANG14=0

for arg in "$@"; do
  case "$arg" in
    --basics)   ENABLE_BASICS=1 ;;
    --net)      ENABLE_NET=1 ;;
    --bpf)      ENABLE_BPF=1 ;;
    --uv)       ENABLE_UV=1 ;;
    --liburing) ENABLE_LIBURING=1 ;;
    --go)       ENABLE_GO=1 ;;
    --clang14)  ENABLE_CLANG14=1 ;;
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
    apt_install llvm libcap-dev flex bison libssl-dev libzstd-dev
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

if [ "$ENABLE_CLANG14" -eq 1 ]; then
  echo "Installing Clang 14 from apt.llvm.org..."

  # Add LLVM apt repo
  apt_install wget gnupg lsb-release software-properties-common
  wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -

  CODENAME="$(lsb_release -cs)"
  echo "deb http://apt.llvm.org/${CODENAME}/ llvm-toolchain-${CODENAME}-14 main" > /etc/apt/sources.list.d/llvm14.list

  apt_update_once

  apt_install clang-14 clangd-14 clang-format-14 clang-tidy-14 lld-14

  # Create symlinks
  ln -sf /usr/bin/clang-14 /usr/local/bin/clang
  ln -sf /usr/bin/clang++-14 /usr/local/bin/clang++
  ln -sf /usr/bin/clang-format-14 /usr/local/bin/clang-format
  ln -sf /usr/bin/clang-tidy-14 /usr/local/bin/clang-tidy

  echo "Clang 14 installed via apt.llvm.org!"
  echo "Default symlinks: clang → clang-14, etc."
  echo "If needed: export PATH=/usr/local/bin:\$PATH"
fi


echo "Done."
