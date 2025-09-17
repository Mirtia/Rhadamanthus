# Rootkit-Suite

This is a collection of repositories and PoCs used for Rhadamanthus testing. It also includes setup scripts for the test VMs.

## Contents

- **bad-bpf/** - A collection of malicious eBPF programs that make use of eBPF's ability to read and write user data in between the usermode program and the kernel
- **bds_lkm_ftrace/** - Linux Loadable Kernel Module Rootkit for Linux Kernel 5.x and 6.x on x86_64 using ftrace to hook syscalls
- **curing/** - A POC of a rootkit that uses `io_uring` to perform different tasks without using any syscalls, making it invisible to security tools
- **Diamorphine/** - A LKM rootkit for Linux Kernels 2.6.x/3.x/4.x/5.x/6.x (x86/x86_64 and ARM64)
- **KillHook/** - A simple LKM that uses ftrace to hook sys_kill
- **scripts/** - Setup and installation scripts

## Installation

**Important:** This repository uses git submodules. You must clone with submodules to get all the components:

```bash
git clone --recursive https://github.com/Mirtia/Rootkit-Suite.git
```

## Usage

This suite contains various rootkit implementations and testing tools. Each subdirectory contains its own documentation and build instructions. Please refer to the individual README files in each component for specific usage instructions.

## Quick Start for Ubuntu 20.04 VM (domU)

For a clean Ubuntu 20.04 VM setup:

1. Clone this repository with submodules:
   ```bash
   sudo apt install git
   git clone --recursive https://github.com/Mirtia/Rootkit-Suite.git
   cd Rootkit-Suite
   ```

2. Install kernel debug symbols and headers:
   ```bash
   sudo ./scripts/kernel_install_dbg.sh
   ```

3. Reboot the system (optional):
   ```bash
   sudo reboot
   ```

4. After reboot, install essential dependencies:
   ```bash
   # Install all components (recommended)
   sudo ./scripts/install_essentials.sh --basics --net --bpf --uv --liburing --go --clang14 --repositories
   
   # Or install specific components as needed:
   # --basics     build-essential, git, headers, python, etc.
   # --net        iproute2, ping, netcat, tcpdump
   # --bpf        bpftrace, bpftool, bpfcc-tools (+ libbpf-dev)
   # --uv         install Astral uv for current user
   # --liburing   build & install liburing + io_uring-cp
   # --go         install Go (default 1.22.6)
   # --clang14    install clang-14 from apt.llvm.org
   # --repositories install repositories (Clueless-Admin)
   ```
