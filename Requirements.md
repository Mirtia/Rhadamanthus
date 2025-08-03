# Architecture

## Description

*Clueless Admin* (See [[Clueless_Admin_README]]) represents the state viewed by the user, even if sometimes it requires root access to communicate with specific interfaces.  It mimics the way a typical monitoring user-space program would highlight events.

On the other hand,  the **Introspector** uses LibVMI in a Xen-based environment and performs event extraction from Dom0 (hypervisor). This means that kernel objects and memory can be examined.

Features can stem from discrepancies observed between the *Clueless Admin* and *Introspector* viewed states (logs).

Volatility acts as an offline analysis tool as a final checker that examines the  memory dumps from the experiments. 

The features collected via this cross-validation method will be used to perform detection via machine learning. Both online and offline detection is supported, since LibVMI is a live introspection framework.

## Experiment Setup

#### Time Window

The time window defines the duration of the monitoring. 
It starts after *Initialization* (*Introspector* and *Clueless Admin* started).  
Ends after *Clueless Attacker* executes *post-actions* and *time window* completes.
#### Initialization

Introspector and *Clueless Admin* are being initiated. The later can be process injected via DRAKVUF, Introspector runs in the Dom0.

#### Loading

Activation of the rootkit.  
Performed via injecting process `insmod` via *DRAKVUF*, with kernel module already pre-compiled and stored in the virtual machine.
Marks the start of *Infection*.
#### Post-actions

Kernel-mode additional traits to take into consideration: there are rootkits that have triggers (e.g. *adoreng*). 

_Clueless Attacker_ imitates post-infection actions (e.g., `ps`, `netstat`, `cat /proc/modules`) that may expose hidden objects or activate rootkit logic.  
These actions are scripted, realistic, and **not bruteforce**.
After a certain time period that the post-actions have been made the experiment terminates.

## Assumptions / Limitations

- The hypervisor is considered trusted. We don't cover rootkits targeting the hypervisor.
- The time window does not cover boot time. So, the detection of bootkits is not covered (future work).

## Requirements

**Initial state**:  <mark style="background: #FFF3A3A6;">Initial state will be collected from a clean DomU machine. </mark> No prior rootkits have been loaded. The initial state can have variations with *stress-ng* running to replicate a more realistic / loaded state of the system.

With <mark style="background: #ABF7F7A6;">cyan</mark> are the features that will be validated with how the state of the system is viewed by a non-kernel mode monitor (*Clueless Admin*) in that case. With <mark style="background: #FF5582A6;">red</mark> (pink), we highlight the points that are questionable and need further exploration.

We split *tasks* dispatched into two categories: 
- **State (StateTask):**
As in *Clueless Admin* periodically check the state of the target structure, e.g. is the IDT table modified? 
- **Event-driven (EventTask):**
Memory events, register events, and so on. They are paired with callback events as defined by LibVMI. LibVMI waits for events in a single thread and process them sequentially.

- [ ] **ftrace hooks**
  - [ ] Check if any new ftrace hooks are registered (most used method since newer kernels for kernel-mode rootkits).
  - [ ] Ftrace is also used by other modules. There are functions that are more likely to be hooked by rootkits.
  - [ ] <mark style="background: #FF5582A6;">With traditional ftrace hooking, there are no traces left on the files?</mark>

- [ ] **network trace**
  - [ ] Scan for open **ports** and active **socket** connections. 
  - [ ] Are the ports that are used by the rootkits getting removed by the hashtable?
  - [ ] <mark style="background: #ABF7F7A6;">Identify any hidden or unreported listening ports. (You don't know if they are hidden :D)</mark>

- [ ] **module list**
  - [ ] Iterate kernel module list from memory. This is already implemented.
  - [ ] <mark style="background: #ABF7F7A6;">Detect hidden or unlinked kernel modules not present in /proc/modules or /sys/module.</mark>

- [ ] **syscall table**
  - [ ] Verify integrity of the syscall table.
  - [ ] There is no equivalent in the *Clueless Admin*.
  - [ ] Applicable mainly to older kernels with unprotected sys_call_table.

- [ ] **IDT hook**
  - [ ] Analyze IDT entries for modifications.
  - [ ] Check for altered interrupt vectors or jump instructions.
  - [ ] Primarily proof-of-concept; modern x86_64 systems use syscall/sysret.

- [ ] **syscall timing**
  - [ ] Measure execution timing of syscalls.
  - [ ] Identify abnormal delays or detours compared to clean baseline.
  - [ ] Use statistical comparison if available.

- [ ] **cr0 writes**
  - [ ] Check for changes to the CR0 register, especially WP (write-protect) bit.
  - [ ] Indicates possible writable kernel text modification.
  - [ ] Only relevant for older or unlocked kernels.

- [ ] **folder (specific strings)**
  - [ ] Scan filesystem for suspicious strings related to known rootkits (e.g., adore, suterusu, phide).
  - [ ] Search for hidden files or directories (e.g., names with null bytes, leading dots, or device-masked entries).
  - [ ] Static signature check.

- [ ] **DKOM (Direct Kernel Object Manipulation)**
  - [ ] Verify consistency of task_struct and process lists.
  - [ ] Identify hidden processes or kernel threads not reflected in /proc.
  - [ ] Check module list manipulation in struct module.

- [ ] **page table and memory mapping**
  - [ ] Validate kernel memory regions are mapped read-only.
  - [ ] Check if syscall table or text segment is remapped writable.
  - [ ] Verify memory layout matches expected kernel map.

- [ ] **sysfs and procfs artifacts**
  - [ ] Examine /proc, /sys, and /dev for anomalous or unregistered entries.
  - [ ] Look for broken links, dummy files, or abnormal device nodes.

- [ ] **netfilter hooks**
  - [ ] Inspect all registered Netfilter hooks.
  - [ ] Confirm callback functions are valid and match expected handlers.

- [ ] **function pointer validation**
  - [ ] Check integrity of function pointer tables: *file_operations*, *net_device_ops*, *inet_protos*, etc.
  - [ ] Verify all pointers reside in kernel text or valid modules.
  - [ ] Flag any pointing to userland or unmapped memory.

- [ ] **hidden kernel threads**
  - [ ] Identify kernel threads not exposed via /proc.
  - [ ] Cross-validate scheduler or task list data from memory.

- [ ] **kprobes/jprobes/kretprobes**
  - [ ] Detect presence of dynamic instrumentation probes.
  - [ ] Check registered probes and compare against expected tracing configurations.

- [ ] **MSR hooking**
  - [ ] Read and verify syscall-related Model-Specific Registers (e.g., MSR_LSTAR, MSR_SYSCALL_TARGET).
  - [ ] Validate target addresses of syscall handlers.

- [ ] **kernel code integrity**
  - [ ] Hash and compare .text segment against known-good baseline.
  - [ ] Detect any unauthorized modification in kernel code section.

- [ ] **introspection integrity**
  - [ ] Ensure introspection tool environment is not tampered with (e.g., introspection bypass via EPT/NPT manipulation).
  - [ ] Validate introspection root trust and page mappings.

- [ ] **io_uring inspection**
  - [ ] List all io_ring_ctx structures.
  - [ ] Identify orphaned or hidden io_uring rings.
  - [ ] Detect abnormal or malicious io_uring-worker threads.
  - [ ] Validate function pointers in io_operations.
  - [ ] Flag persistent or unreferenced pinned user buffers.
  - [ ] Check for misuse of submission queue entries for arbitrary kernel execution.

- [ ] **eBPF rootkit detection**
  - [ ] Enumerate loaded eBPF programs via bpffs or introspection.
  - [ ] Identify BPF programs attached to:
    - [ ] kprobes
    - [ ] tracepoints
    - [ ] uprobes
    - [ ] syscall entry/exit points
    - [ ] networking hooks (XDP, tc, sock_ops, etc.)
  - [ ] Cross-check attached BPF programs against legitimate tools (e.g., systemd, container runtime).
  - [ ] Examine BPF maps for:
    - [ ] Persistent key/value pairs used for hiding (e.g., PID filters)
    - [ ] Backdoor triggers or exfiltration channels
  - [ ] Analyze BPF bytecode or JIT cache for suspicious logic (e.g., syscall manipulation, credential filtering).
  - [ ] Check for BPF programs with no associated user-space loader (potentially injected via privileged process).
  - [ ] Verify if `bpf` syscall is restricted (via seccomp or LSM).
  - [ ] Detect manipulation of `bpf_prog_array`, `bpf_map_array`, or tail call maps to hide programs.
  - [ ] Monitor audit logs or trace for `bpf()` or `perf_event_open()` syscalls used for program injection.

- [ ] **credential tampering**
  - [ ] Traverse task_struct list and validate each process's credentials.
  - [ ] Check for any process with uid, euid, suid, fsuid = 0 not belonging to init/system processes.
  - [ ] Confirm that real_cred and cred pointers are consistent and not substituted.
  - [ ] Identify abnormal capability sets (cap_eff, cap_inh, cap_permitted).
  - [ ] Look for use of get_cred/prepare_kernel_cred with commit_creds in backtraces or hooks.

- [ ] **kallsyms manipulation**
  - [ ] Compare in-memory kernel symbol table with expected symbol layout.
  - [ ] Detect missing or NULLed entries in /proc/kallsyms or in-memory kallsyms structures.
  - [ ] Validate address-to-symbol resolution works for syscall table, commit_creds, prepare_kernel_cred, etc.
  - [ ] Confirm kallsyms visibility is not disabled via kptr_restrict or LSM.
  - [ ] Scan for alternative symbol resolution methods (e.g., static symbol resolution tables in memory).

- [ ] **firmware/efi/acpi hooks**
  - [ ] Check for runtime services table (EFI Runtime Services) hooks or pointer redirection.
  - [ ] Scan UEFI variables for persistence payloads or altered boot order entries.
  - [ ] Verify integrity of EFI memory maps and system table pointers.
  - [ ] Identify modified or non-standard ACPI tables (DSDT, SSDT, etc.) that may invoke malicious methods.
  - [ ] Detect System Management Mode (SMM) or runtime ACPI method abuse (e.g., via _WAK, _PTS, _GTS).
  - [ ] Look for platform firmware that writes into OS memory post-boot (via ACPI or MMIO windows).

### Requirements Table

| Feature / Task                     | EventTask | StateTask | Pause? | Clueless Admin Equivalent |
| ---------------------------------- | --------- | --------- | ------ | ------------------------- |
| **ftrace hooks**                   | ✅         | ✅         | ⛔      | 👁️ (`--ftrace`)          |
| **network trace**                  | ❌         | ✅         | 🟢     | 👁️ (`--networking`)      |
| **module list**                    | ❌         | ✅         | ⛔      | 👁️ (`--modules`)         |
| **syscall table**                  | ✅         | ✅         | ⛔      | ❌                         |
| **IDT hook**                       | ✅         | ✅         | ⛔      | ❌                         |
| **syscall timing**                 | ❌         | ✅         | 🟢     | 👁️ (via `--process`)     |
| **cr0 writes**                     | ✅         | ❌         | 🟢     | ❌                         |
| **folder string scan**             | ❌         | ✅         | 🟢     | 👁️ (`--file-system`)     |
| **DKOM (process list)**            | ❌         | ✅         | ⛔      | 👁️ (`--process`)         |
| **page table / mem mapping**       | ✅         | ✅         | ⛔      | ❌                         |
| **sysfs / procfs artifacts**       | ❌         | ✅         | 🟢     | 👁️ (`--file-system`)     |
| **netfilter hooks**                | ✅         | ✅         | ⛔      | 👁️ (`--networking`)      |
| **function pointer validation**    | ✅         | ✅         | ⛔      | ❌                         |
| **hidden kernel threads**          | ❌         | ✅         | ⛔      | 👁️ (`--process`)         |
| **kprobes / jprobes / kretprobes** | ❌         | ✅         | ⛔      | 👁️ (`--ebpf`)            |
| **MSR hooking**                    | ✅         | ✅         | 🟢/⛔   | ❌                         |
| **kernel code integrity**          | ✅         | ✅         | ⛔      | ❌                         |
| **introspection integrity**        | ✅         | ✅         | ⛔      | ❌                         |
| **io_uring inspection**            | ✅         | ✅         | ⛔      | 👁️ (`--io-uring`)        |
| **eBPF rootkit detection**         | ✅         | ✅         | ⛔      | 👁️ (`--ebpf`)            |
| **credential tampering**           | ❌         | ✅         | ⛔      | 👁️ (`--process`)         |
| **kallsyms manipulation**          | ✅         | ✅         | ⛔      | ❌                         |
| **firmware / EFI / ACPI hooks**    | ❌         | ✅         | ⛔      | ❌                         |

## Scripting / Helpers

- [ ] Setup scripts
- [ ] Saving states / loading states scripts
- [ ] Volatility post-analysis scripts
- [ ] Timing / automation scripts

## Code Architecture

- [ ] JSON schema for answers. (*Clueless Admin* should align with the *Introspector* and *Clueless Attacker*)
- [ ] Dispatcher
- [ ] YAML schema
