# Rhadamanthus - VMI Linux Rootkit Feature Collection

[![License: LGPL v2.1](https://img.shields.io/badge/License-LGPL%20v2.1-blue.svg)](https://www.gnu.org/licenses/lgpl-2.1)
[![C Standard](https://img.shields.io/badge/C%20Standard-C99-blue.svg)](https://en.wikipedia.org/wiki/C99)

> Warning: This project is work of an MSc Thesis while being extremely burnout. There may be mistakes, there may be things that built on wrong assumptions! I still plan to continue working on it after my submission...

A Virtual Machine Introspection (VMI) framework for detecting Linux rootkits and malicious kernel modifications using LibVMI. This project is designed to help with collecting information about potential rootkit indicators in a running system. It can be used as a baseline to later on develop a machine learning approach for linux kernel-mode rootkit detection.

🤔 If I had to pitch this, it could be amateurish downgraded untested DRAKVUF that focuses in kernel-mode rootkit detection and has a response format I prefer!

## Overview

The VMI Linux Rootkit Feature Collection uses Virtual Machine Introspection (LibVMI) to detect various types of rootkits and kernel-level attacks.

### Key Features

- **Multi-Modal Detection**: State polling, event-driven, and interrupt-based monitoring
- **Comprehensive Coverage**: Detects ftrace hooks, syscall table modifications, IDT hooks, and more.
- **Real-time Monitoring**: Live detection with configurable sampling intervals.
- **Structured Output**: JSON-based reporting following Google's response schema.
- **Extensible Architecture**: Modular design for easy addition of new detection methods.

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

### Setup that worked


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

## ⚙️ Configuration

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
- `STATE_NETWORK_TRACE` - Monitors network connections (`src/state_callbacks/network_trace.c`)
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
- `EVENT_MSR_WRITE` - Model Specific Register monitoring (`src/event_callbacks/msr_write.c`)
- `EVENT_CODE_SECTION_MODIFY` - Code section modification detection (`src/event_callbacks/code_section_modify.c`)
- `EVENT_PAGE_TABLE_MODIFICATION` - Page table modification detection (`src/event_callbacks/page_table_modification.c`)
- `EVENT_KALLSYMS_TABLE_WRITE` - Kernel symbol table modification (`src/event_callbacks/kallsyms_table_write.c`)
- `EVENT_NETFILTER_HOOK_WRITE` - Netfilter hook modification (`src/event_callbacks/netfilter_hook_write.c`)
- `EVENT_IO_URING_RING_WRITE` - io_uring ring buffer modification (`src/event_callbacks/io_uring_ring_write.c`)

#### Interrupt Tasks
- `INTERRUPT_EBPF_PROBE` - eBPF probe breakpoint monitoring (`src/event_callbacks/ebpf_probe.c`)
- `INTERRUPT_IO_URING_RING_WRITE` - io_uring ring buffer monitoring (`src/event_callbacks/io_uring_ring_write.c`)
- `INTERRUPT_NETFILTER_HOOK_WRITE` - Netfilter hook monitoring (`src/event_callbacks/netfilter_hook_write.c`)

## 📊 Output Format

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

## 🧪 Testing

The project includes comprehensive unit tests and proof-of-concept demonstrations:

```bash
# Run all tests
make test

# Run specific test suites
./build/test_config_parser
./build/test_event_handler
./build/test_state_callbacks_syscall_table

# Run proof-of-concept tests
cd tests/poc/
make -C idt_hook_poc/
make -C msr_lstar_poc/
```

## 🔧 Development

### Building from Source


### Adding New Detection Features

1. **Create callback module** in `src/state_callbacks/` or `src/event_callbacks/`
2. **Add response handler** in corresponding `responses/` directory
3. **Update task maps** in `src/state_task_map.c` or `src/event_task_map.c`
4. **Add configuration option** in `config/settings_schema.yaml`
5. **Write tests** in `tests/` directory

## 📚 Documentation

- [API Documentation](docs/api/) - Detailed API reference
- [Configuration Guide](docs/configuration.md) - Configuration options
- [Detection Methods](docs/detection-methods.md) - How each detection method works
- [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Ensure all tests pass: `make test`
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

## 📄 License

This project is licensed under the GNU Lesser General Public License v2.1 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **LibVMI** - Virtual Machine Introspection library
- **Xen Project** - Hypervisor platform
- **GLib** - Core application building blocks

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

Or in plain text:

> Gkolemi, M. (2025). VMI Linux Rootkit Feature Collection. Retrieved from https://github.com/Mirtia/VMI-Linux-Rootkit-Feature-Collection

## 📖 References

### Academic Papers

1. **Payne, B. D., Carbone, M., & Sharif, M. (2008).** *Lares: An architecture for secure active monitoring using virtualization.* Proceedings of the 2008 IEEE Symposium on Security and Privacy (pp. 233-247). IEEE.

2. **Garfinkel, T., & Rosenblum, M. (2003).** *A virtual machine introspection based architecture for intrusion detection.* Proceedings of the Network and Distributed System Security Symposium (pp. 191-206). Internet Society.

3. **Bahram, S., Jiang, X., Wang, Z., Grace, M., Li, J., Srinivasan, D., ... & Xu, D. (2010).** *DKSM: Subverting virtual machine introspection for fun and profit.* Proceedings of the 29th IEEE Symposium on Reliable Distributed Systems (pp. 82-91). IEEE.

4. **Dinaburg, A., Royal, P., Sharif, M., & Lee, W. (2008).** *Ether: Malware analysis via hardware virtualization extensions.* Proceedings of the 15th ACM Conference on Computer and Communications Security (pp. 51-62). ACM.

### Technical Documentation

5. **LibVMI Project.** *LibVMI: A Virtual Machine Introspection Library.* Retrieved from https://github.com/libvmi/libvmi

6. **Xen Project.** *Xen Hypervisor Documentation.* Retrieved from https://xenproject.org/developers/teams/hypervisor.html

7. **Linux Kernel Documentation.** *Ftrace: Function Tracer.* Retrieved from https://www.kernel.org/doc/Documentation/trace/ftrace.txt

8. **Intel Corporation.** *Intel 64 and IA-32 Architectures Software Developer's Manual.* Volume 3A: System Programming Guide, Part 1.

### Rootkit Detection Research

9. **Rutkowska, J. (2006).** *Subverting Vista kernel for fun and profit.* Black Hat USA 2006.

10. **Butler, J., & Sparks, S. (2005).** *Windows rootkits of 2005, part one.* Symantec Security Response.

11. **Hoglund, G., & Butler, J. (2005).** *Rootkits: Subverting the Windows kernel.* Addison-Wesley Professional.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Mirtia/VMI-Linux-Rootkit-Feature-Collection/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Mirtia/VMI-Linux-Rootkit-Feature-Collection/discussions)
- **Email**: [Contact Information]

## 🔗 Related Projects

- [LibVMI](https://github.com/libvmi/libvmi) - Virtual Machine Introspection library
- [Xen Project](https://xenproject.org/) - Hypervisor platform
- [Clueless Admin](https://github.com/Mirtia/Clueless-Admin) - Related security analysis tool

---

**⚠️ Security Notice**: This tool is designed for authorized security testing and research purposes only. Ensure you have proper authorization before using it on any systems.
