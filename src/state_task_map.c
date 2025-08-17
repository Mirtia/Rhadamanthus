#include "state_task_map.h"
#include <log.h>

#include "state_callbacks/dir_string_matching.h"
#include "state_callbacks/ebpf_artifacts.h"
#include "state_callbacks/firmware_acpi_hooks.h"
#include "state_callbacks/ftrace_hooks.h"
#include "state_callbacks/idt_table.h"
#include "state_callbacks/io_uring_artifacts.h"
#include "state_callbacks/kallsyms_symbols.h"
#include "state_callbacks/kernel_code_integrity_check.h"
#include "state_callbacks/kernel_module_list.h"
#include "state_callbacks/msr_registers.h"
#include "state_callbacks/network_trace.h"
#include "state_callbacks/process_list.h"
#include "state_callbacks/syscall_table.h"

uint32_t (*get_state_task_functor(state_task_id_t task_id))(vmi_instance_t,
                                                            void*) {
  switch (task_id) {
    case STATE_DIR_STRING_MATCHING:
      return state_dir_string_matching_callback;
    case STATE_EBPF_ARTIFACTS:
      return state_ebpf_artifacts_callback;
    case STATE_FIRMWARE_ACPI_HOOKS:
      return state_firmware_acpi_hooks_callback;
    case STATE_FTRACE_HOOKS:
      return state_ftrace_hooks_callback;
    case STATE_IDT_TABLE:
      return state_idt_table_callback;
    case STATE_IO_URING_ARTIFACTS:
      return state_io_uring_artifacts_callback;
    case STATE_KALLSYMS_SYMBOLS:
      return state_kallsyms_symbols_callback;
    case STATE_KERNEL_CODE_INTEGRITY_CHECK:
      return state_kernel_code_integrity_check_callback;
    case STATE_KERNEL_MODULE_LIST:
      return state_kernel_module_list_callback;
    case STATE_MSR_REGISTERS:
      return state_msr_registers_callback;
    case STATE_NETWORK_TRACE:
      return state_network_trace_callback;
    case STATE_PROCESS_LIST:
      return state_process_list_callback;
    case STATE_SYSCALL_TABLE:
      return state_syscall_table_callback;
    default:
      log_warn("Unknown state task ID: %d", task_id);
      return NULL;
  }
}