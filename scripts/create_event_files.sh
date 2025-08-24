#!/bin/bash

# List of all event task names
event_tasks=(
  ftrace_hook
  syscall_table_write
  idt_write
  cr0_write
  page_table_modification
  netfilter_hook_write
  msr_write
  code_section_modify
  io_uring_ring_write
  ebpf_map_update
  kallsyms_table_write
)

# Create header and source files for each
for task in "${event_tasks[@]}"; do
  touch "../include/event_callbacks/${task}.h"
  touch "../src/event_callbacks/${task}.c"
done