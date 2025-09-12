# Rhadamanthus - VMI Linux Rootkit Feature Collection

[![License: LGPL v2.1](https://img.shields.io/badge/License-LGPL%20v2.1-blue.svg)](https://www.gnu.org/licenses/lgpl-2.1)
[![C Standard](https://img.shields.io/badge/C%20Standard-C99-blue.svg)](https://en.wikipedia.org/wiki/C99)

> Warning: This project is the outcome of an MSc Thesis while being extremely burnout. There may be mistakes, there may be things that are built on wrong assumptions! I still plan to continue working on this project after my submission...

A Virtual Machine Introspection (VMI) framework for detecting Linux rootkits and malicious kernel modifications using LibVMI. This project is designed to help with collecting information about potential rootkit indicators on a running virtual machine (Dom0) using a privileged virtual machine (DomU). It can be used as a base later on, to develop a machine learning approach for linux kernel-mode rootkit detection.

🤔 If I had to pitch this, I would say "An amateurish downgraded untested DRAKVUF that focuses in kernel-mode rootkit detection and has a response format I prefer".

## Overview

The VMI Linux Rootkit Feature Collection uses [LibVMI](https://libvmi.com/) for detection.

## System

The framework was built and run under the following system requirements:
```sh
OS: Debian GNU/Linux 12 (bookworm) x86_64
Xen: xen-hypervisor-4.20.0-debian-bookworm-amd64
Drakvuf build: drakvuf-bundle-1.1-0fa2fd6-debian-bookworm
```

## Architecture

The project follows a modular, event-driven architecture with three main detection paradigms.


### Core Components

```
├── src/
│   ├── event_handler.c          # Main event loop and task coordination
│   ├── config_parser.c          # YAML configuration parsing
│   ├── json_serializer.c        # Structured output generation
│   ├── state_callbacks/         # State-based detection modules
│   ├── event_callbacks/         # Event-based detection modules
│   └── utils.c                  # Common utilities and error handling
├── include/                     # Header files and API definitions
├── tests/                       # Unit tests and proof-of-concepts
└── config/                      # Configuration templates
```

## Quick Start

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Mirtia/VMI-Linux-Rootkit-Feature-Collection.git
   cd VMI-Linux-Rootkit-Feature-Collection
   ```

2. **Install dependencies**
   ```bash
   # Install Conan (if not already installed)
   pip install conan

   # Install project dependencies
   make build
   ```

3. **Configure LibVMI**
   ```bash
   # Edit /etc/libvmi.conf to include your VM domain
   sudo nano /etc/libvmi.conf
   ```

4. **Create configuration file**
   ```bash
   cp config/settings_schema.yaml my_config.yaml
   # Edit my_config.yaml with your VM domain name
   ```

5. **Run the introspector**
   ```bash
   ./build/introspector -c my_config.yaml
   ```

## Configuration

The project uses YAML configuration files to specify monitoring parameters and detection features.

### Basic Configuration

```yaml
# VM domain name (must match LibVMI configuration)
domain_name: "ubuntu-20-04-new-kernel"

# Monitoring parameters
monitor:
  window_ms: 10000        # Total monitoring window (10 seconds)
  state_sampling_ms: 1000 # State polling interval (1 second)

# Detection features
features:
  state:
    - id: STATE_FTRACE_HOOKS      # Detect ftrace-based hooks
    - id: STATE_SYSCALL_TABLE     # Monitor syscall table integrity
    - id: STATE_NETWORK_TRACE     # Analyze network connections
  
  event:
    - id: EVENT_FTRACE_HOOK       # Real-time ftrace hook detection
  
  interrupt:
    - id: INTERRUPT_EBPF_PROBE    # eBPF probe monitoring
```

### Available Detection Features

#### State Tasks
- `STATE_FTRACE_HOOKS` - Detects ftrace-based function hooks (`src/state_callbacks/ftrace_hooks.c`)
- `STATE_SYSCALL_TABLE` - Monitors syscall table integrity (`src/state_callbacks/syscall_table.c`)
- `STATE_IDT_TABLE` - Verifies Interrupt Descriptor Table (`src/state_callbacks/idt_table.c`)
- `STATE_KERNEL_MODULE_LIST` - Analyzes loaded kernel modules (`src/state_callbacks/kernel_module_list.c`)
- `STATE_NETWORK_TRACE` - Monitors network connections and hooks (`src/state_callbacks/network_trace.c`)
- `STATE_EBPF_ARTIFACTS` - Detects eBPF programs and maps (`src/state_callbacks/ebpf_activity.c`)
- `STATE_IO_URING_ARTIFACTS` - Monitors io_uring structures (`src/state_callbacks/io_uring_artifacts.c`)
- `STATE_MSR_REGISTERS` - Monitors Model Specific Registers (`src/state_callbacks/msr_registers.c`)
- `STATE_PROCESS_LIST` - Analyzes running processes (`src/state_callbacks/process_list.c`)
- `STATE_KALLSYMS_SYMBOLS` - Monitors kernel symbol table (`src/state_callbacks/kallsyms_symbols.c`)
- `STATE_DIR_STRING_MATCHING` - String matching in directories (`src/state_callbacks/dir_string_matching.c`) (NOT IMPLEMENTED)

#### Event Tasks
- `EVENT_FTRACE_HOOK` - Real-time ftrace hook detection (`src/event_callbacks/ftrace_hook.c`)
- `EVENT_SYSCALL_TABLE_WRITE` - Syscall table modification events (`src/event_callbacks/syscall_table_write.c`)
- `EVENT_IDT_WRITE` - IDT modification detection (`src/event_callbacks/idt_write.c`)
- `EVENT_CR0_WRITE` - CR0 register modification detection (`src/event_callbacks/cr0_write.c`)
- `EVENT_MSR_WRITE` - MSR monitoring (`src/event_callbacks/msr_write.c`)
- `EVENT_CODE_SECTION_MODIFY` - Code section modification detection (`src/event_callbacks/code_section_modify.c`)
- `EVENT_PAGE_TABLE_MODIFICATION` - Page table modification detection (`src/event_callbacks/page_table_modification.c`)
- `EVENT_KALLSYMS_TABLE_WRITE` - Kernel symbol table modification (`src/event_callbacks/kallsyms_table_write.c`)
- `EVENT_NETFILTER_HOOK_WRITE` - Netfilter hook modification (`src/event_callbacks/netfilter_hook_write.c`)
- `EVENT_IO_URING_RING_WRITE` - io_uring __x64_sys_io_uring_enter (`src/event_callbacks/io_uring_ring_write.c`)

#### Interrupt Tasks
- `INTERRUPT_EBPF_PROBE` - eBPF probe breakpoint monitoring (`src/event_callbacks/ebpf_probe.c`)
- `INTERRUPT_IO_URING_RING_WRITE` - io_uring ring buffer monitoring (`src/event_callbacks/io_uring_ring_write.c`)
- `INTERRUPT_NETFILTER_HOOK_WRITE` - Netfilter hook monitoring (`src/event_callbacks/netfilter_hook_write.c`)

## Response Format

The introspector generates structured JSON output following Google's response schema:

```json
{
  "timestamp": "2025-01-15T10:30:45.123Z",
  "status": "SUCCESS",
  "metadata": {
    "task_type": "STATE",
    "subtype": "STATE_FTRACE_HOOKS"
  },
  "data": {
    "hooks_detected": 2,
    "hooks": [
      {
        "function_name": "sys_openat",
        "original_address": "0xffffffff81234567",
        "hooked_address": "0xffffffffc0001234",
        "hook_type": "ftrace_hook",
        "attachment_type": "syscall"
      }
    ]
  }
}
```

## 📄 License

This project is licensed under the GNU Lesser General Public License v2.1 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **LibVMI** - Virtual Machine Introspection library.
- **Xen Project** - Hypervisor platform.
- **DRAKVUF** - Virtualization based agentless black-box binary analysis system.

## 📚 Citation

If you use this project in your research, please cite it as:

```bibtex
@software{vmi_rootkit_detection,
  title={VMI Linux Rootkit Feature Collection},
  author={Gkolemi, Myrsini},
  year={2025},
  url={https://github.com/Mirtia/VMI-Linux-Rootkit-Feature-Collection},
  license={LGPL-2.1}
}
```
