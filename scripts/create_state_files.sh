#!/bin/bash

# List of all state task names
# Note: Some of the tasks have been removed due to being determined out of scope / no PoC existing for the analysis.
state_tasks=(
  kernel_module_list
  ftrace_hooks
  network_trace
  syscall_table
  idt_table
  dir_string_matching
  process_list
  procfs_artifacts
  netfilter_hooks
  kernel_threads
  kprobes_jprobes_kretprobes
  msr_registers
  kernel_code_integrity_check
  ebpf_artifacts
  io_uring_artifacts
  credentials
  kallsyms_symbols
  firmware_acpi_hooks
)

# Create header and source files for each
for task in "${state_tasks[@]}"; do
  touch "../include/state_callbacks/${task}.h"
  touch "../src/state_callbacks/${task}.c"
done