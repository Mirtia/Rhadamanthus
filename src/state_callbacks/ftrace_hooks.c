#include "state_callbacks/ftrace_hooks.h"
#include <glib.h>
#include <inttypes.h>
#include <log.h>
#include <string.h>
#include "event_handler.h"
#include "offsets.h"
#include "state_callbacks/responses/ftrace_hooks_response.h"
#include "utils.h"

#define MAX_BACKTRACK_BYTES 128
#define MAX_FTRACE_PAGES 64
#define MAX_MCOUNT_ENTRIES 2000

/**
 * @brief Rootkit target structure
 * 
 * @param symbol_name The name of the rootkit target function.
 * @param addr_ptr Pointer to the resolved address of the rootkit target function.
 */
typedef struct {
  const char* symbol_name;  ///< The name of the rootkit target function.
  addr_t*
      addr_ptr;  ///< Pointer to the resolved address of the rootkit target function.
} rootkit_target_t;

/**
 * @brief Resolve an address to its enclosing function symbol with offset
 * 
 * @details Implements the "nearest-lower symbol" approach for resolving addresses that
 * may be inside function prologues (e.g., ftrace call sites at func+0x4).
 * The algorithm first attempts exact symbol resolution via LibVMI's symbol table.
 * If that fails, it backtracks byte-by-byte up to MAX_BACKTRACK_BYTES to find
 * the nearest function symbol with a lower address, then calculates the offset.
 * This handles cases where the address points to instrumentation within a function.
 * 
 * @param vmi LibVMI instance
 * @param address The address to resolve
 * @return Newly allocated string in format "function_name+0xoffset" or NULL on failure.
 *         Caller must free with g_free().
 */
static char* resolve_enclosing_symbol_pretty(vmi_instance_t vmi,
                                             addr_t address) {
  access_context_t ctx = {.version = ACCESS_CONTEXT_VERSION,
                          .translate_mechanism = VMI_TM_NONE,
                          .addr = address};

  const char* symbol_name = vmi_translate_v2ksym(vmi, &ctx, address);
  if (symbol_name) {
    return g_strdup(symbol_name);
  }
  for (addr_t backtrack = 1; backtrack <= MAX_BACKTRACK_BYTES; backtrack++) {
    addr_t candidate = address - backtrack;
    ctx.addr = candidate;

    symbol_name = vmi_translate_v2ksym(vmi, &ctx, candidate);
    if (symbol_name) {
      uint64_t offset = address - candidate;
      return g_strdup_printf("%s+0x%" PRIx64, symbol_name, offset);
    }
  }

  return NULL;
}

/**
 * @brief Known rootkit targets for ftrace hooking.
 * 
 * @param symbol_name The name of the rootkit target function.
 * @param addr_ptr Pointer to the resolved address of the rootkit target function.
 */
static rootkit_target_t known_rootkit_targets[] = {
    {"tcp4_seq_show", NULL},
    {"tcp6_seq_show", NULL},
    {"udp4_seq_show", NULL},
    {"udp6_seq_show", NULL},
    {"inet_csk_accept", NULL},
    {"tcp_v4_connect", NULL},
    {"tcp_v6_connect", NULL},

    {"__x64_sys_getdents64", NULL},
    {"__x64_sys_getdents", NULL},
    {"__x64_sys_openat", NULL},
    {"__x64_sys_open", NULL},
    {"__x64_sys_read", NULL},
    {"__x64_sys_write", NULL},
    {"__x64_sys_stat", NULL},
    {"__x64_sys_lstat", NULL},
    {"__x64_sys_fstat", NULL},
    {"__x64_sys_newstat", NULL},
    {"__x64_sys_newlstat", NULL},
    {"__x64_sys_newfstat", NULL},
    {"__x64_sys_statx", NULL},

    {"__x64_sys_kill", NULL},
    {"__x64_sys_tgkill", NULL},
    {"__x64_sys_killpg", NULL},
    {"__x64_sys_wait4", NULL},
    {"__x64_sys_waitid", NULL},
    {"__x64_sys_waitpid", NULL},
    {"__x64_sys_ptrace", NULL},

    {"__x64_sys_mmap", NULL},
    {"__x64_sys_munmap", NULL},
    {"__x64_sys_mprotect", NULL},
    {"__x64_sys_brk", NULL},

    {"__x64_sys_init_module", NULL},
    {"__x64_sys_delete_module", NULL},
    {"__x64_sys_finit_module", NULL},

    {"__x64_sys_capset", NULL},
    {"__x64_sys_capget", NULL},
    {"__x64_sys_setuid", NULL},
    {"__x64_sys_setgid", NULL},
    {"__x64_sys_setreuid", NULL},
    {"__x64_sys_setregid", NULL},
    {"__x64_sys_setresuid", NULL},
    {"__x64_sys_setresgid", NULL},

    {"__x64_sys_socket", NULL},
    {"__x64_sys_bind", NULL},
    {"__x64_sys_listen", NULL},
    {"__x64_sys_accept", NULL},
    {"__x64_sys_connect", NULL},
    {"__x64_sys_sendto", NULL},
    {"__x64_sys_recvfrom", NULL},

    {"__x64_sys_uname", NULL},
    {"__x64_sys_sysinfo", NULL},
    {"__x64_sys_getpid", NULL},
    {"__x64_sys_getppid", NULL},
    {"__x64_sys_getuid", NULL},
    {"__x64_sys_getgid", NULL},
    {"__x64_sys_geteuid", NULL},
    {"__x64_sys_getegid", NULL},

    {"__x64_sys_time", NULL},
    {"__x64_sys_gettimeofday", NULL},
    {"__x64_sys_clock_gettime", NULL},

    {NULL, NULL}  // Sentinel
};

/**
 * @brief Resolve known rootkit target function addresses.
 * 
 * @details Resolves all known rootkit target function names to their virtual addresses
 * and stores them in the known_rootkit_targets array for later use in direct
 * memory scanning. Uses a static array to store resolved addresses to ensure each target gets
 * a unique address pointer, preventing all targets from resolving to the same
 * address due to pointer reuse.
 * 
 * @param vmi LibVMI instance.
 */
static void resolve_rootkit_targets(vmi_instance_t vmi) {
  static addr_t resolved_addresses[100];
  int addr_index = 0;

  for (int i = 0; known_rootkit_targets[i].symbol_name != NULL; i++) {
    addr_t addr = 0;
    if (vmi_translate_ksym2v(vmi, known_rootkit_targets[i].symbol_name,
                             &addr) == VMI_SUCCESS) {
      resolved_addresses[addr_index] = addr;
      known_rootkit_targets[i].addr_ptr = &resolved_addresses[addr_index];
      addr_index++;
    }
  }
}

/**
 * @brief Determine the attachment type based on function name and characteristics.
 * 
 * @details Analyzes the function name and other characteristics to determine the most
 * likely ftrace attachment type. This helps classify hooks into categories
 * like syscall, kprobe, fentry, etc.
 * 
 * @param function_name The name of the hooked function.
 * @param is_syscall Whether this appears to be a syscall function.
 * @return String describing the attachment type.
 */
static const char* determine_attachment_type(const char* function_name,
                                             bool is_syscall) {
  if (is_syscall) {
    return "syscall";
  }

  if (function_name) {
    // Check for common patterns
    if (strstr(function_name, "sys_") != NULL) {
      return "syscall";
    }
    if (strstr(function_name, "tcp") != NULL ||
        strstr(function_name, "udp") != NULL) {
      return "network";
    }
    if (strstr(function_name, "file") != NULL ||
        strstr(function_name, "inode") != NULL) {
      return "filesystem";
    }
    if (strstr(function_name, "process") != NULL ||
        strstr(function_name, "task") != NULL) {
      return "process";
    }
  }

  return "fentry";
}

/**
 * @brief Determine the hook type based on detection method and characteristics.
 * 
 * @param detection_method How the hook was detected.
 * @param attachment_type The attachment type determined above.
 * @return String describing the hook type.
 */
static const char* determine_hook_type(const char* detection_method,
                                       const char* attachment_type) {
  if (strcmp(detection_method, "direct_scan") == 0) {
    return "ftrace_hook";
  }
  if (strcmp(attachment_type, "syscall") == 0) {
    return "syscall_hook";
  }
  return "ftrace_hook";
}

/**
 * @brief Perform direct memory scanning for ftrace hooks in known target functions
 * 
 * Bypasses potentially corrupted ftrace data structures by directly scanning
 * the first 64 bytes of each known rootkit target function for CALL instructions
 * (0xE8) that point to addresses in the rootkit module range (0xffffffffc0...).
 * 
 * This is a reliable method to detect ftrace hooks even when kernel data
 * structures are corrupted. The scan looks for CALL instructions with targets
 * in the typical kernel module address range, which indicates a rootkit has
 * patched the function prologue to redirect execution to its own code.
 * 
 * @param vmi The LibVMI instance.
 * @param data State data structure to populate with detected hooks.
 * @param hook_id Pointer to current hook ID counter (will be incremented).
 * @param suspicious_count Pointer to suspicious count counter (will be incremented).
 */
static void scan_for_direct_hooks(vmi_instance_t vmi,
                                  ftrace_hooks_state_data_t* data,
                                  // NOLINTNEXTLINE
                                  uint32_t* hook_id,
                                  uint32_t* suspicious_count) {
  log_debug("Starting direct memory scan of known rootkit targets.");
  int targets_checked = 0;
  int targets_with_addresses = 0;

  for (int j = 0; known_rootkit_targets[j].symbol_name != NULL; j++) {
    targets_checked++;
    if (known_rootkit_targets[j].addr_ptr) {
      targets_with_addresses++;
      addr_t target_addr = *(known_rootkit_targets[j].addr_ptr);

      // Scan first 64 bytes of function for suspicious CALL/JMP instructions
      // Ftrace typically patches the first few bytes of function prologues
      // See: https://www.kernel.org/doc/Documentation/trace/ftrace-design.txt
      for (addr_t check_addr = target_addr; check_addr < target_addr + 0x40;
           check_addr++) {
        uint8_t byte1 = 0;
        if (vmi_read_8_va(vmi, check_addr, 0, &byte1) == VMI_SUCCESS &&
            // Check for x86-64 CALL (0xE8) and JMP (0xE9) opcodes
            // Intel Manual Vol. 2A: "CALL—Call Procedure" and "JMP—Jump"
            // These opcodes use 32-bit relative addressing: E8/E9 <4-byte offset>
            (byte1 == 0xE8 || byte1 == 0xE9)) {
          int32_t call_offset = 0;
          if (vmi_read_32_va(vmi, check_addr + 1, 0, (uint32_t*)&call_offset) ==
              VMI_SUCCESS) {
            addr_t call_target = check_addr + 5 + (int64_t)call_offset;

            if (call_target >= LINUX_MODULE_START &&
                call_target <= LINUX_MODULE_END) {

              bool is_syscall = (strstr(known_rootkit_targets[j].symbol_name,
                                        "__x64_sys_") != NULL);
              const char* attach_type = determine_attachment_type(
                  known_rootkit_targets[j].symbol_name, is_syscall);
              const char* hook_type =
                  determine_hook_type("direct_scan", attach_type);

              ftrace_hooks_state_add_hook(data, *hook_id, hook_type,
                                          known_rootkit_targets[j].symbol_name,
                                          attach_type, target_addr, "0x1857",
                                          call_target, target_addr, true,
                                          "Function hooked by rootkit module");

              ftrace_hooks_state_add_attachment_point(data, attach_type,
                                                      *hook_id);

              (*hook_id)++;
              (*suspicious_count)++;
              log_debug("Found hook in %s at 0x%" PRIx64 " -> 0x%" PRIx64,
                        known_rootkit_targets[j].symbol_name,
                        (uint64_t)check_addr, (uint64_t)call_target);
              break;
            }
          }
        }
      }
    }
  }

  log_debug(
      "Direct scan completed: checked %d targets, %d had addresses, found %u "
      "hooks.",
      targets_checked, targets_with_addresses, *suspicious_count);
}

/**
 * @brief Analyze ftrace operations for suspicious hooks
 * 
 * Walks the ftrace_ops_list to find registered ftrace operations and checks
 * if their callback functions are outside the kernel text range, which would
 * indicate potential rootkit hooks.
 * 
 * The ftrace_ops_list contains all registered ftrace operations. Each operation
 * has a callback function pointer that should normally point to kernel code.
 * If the callback points outside the kernel text range, it likely indicates
 * a rootkit has registered its own callback function.
 * 
 * @see include/linux/ftrace.h for struct ftrace_ops definition
 * @param vmi LibVMI instance
 * @param data State data structure to populate with detected hooks
 * @param kernel_start Start of kernel text section
 * @param kernel_end End of kernel text section
 * @param hook_id Pointer to current hook ID counter (will be incremented)
 * @param suspicious_count Pointer to suspicious count counter (will be incremented)
 */
static void analyze_ftrace_operations(vmi_instance_t vmi,
                                      ftrace_hooks_state_data_t* data,
                                      addr_t kernel_start, addr_t kernel_end,
                                      // NOLINTNEXTLINE
                                      uint32_t* hook_id,
                                      uint32_t* suspicious_count) {
  addr_t ftrace_ops_list = 0;
  log_debug("Attempting to resolve ftrace_ops_list symbol.");

  if (vmi_translate_ksym2v(vmi, "ftrace_ops_list", &ftrace_ops_list) !=
      VMI_SUCCESS) {
    log_debug("Failed to resolve ftrace_ops_list symbol.");
    return;
  }

  log_debug("Resolved ftrace_ops_list at 0x%" PRIx64,
            (uint64_t)ftrace_ops_list);

  addr_t current_ops = ftrace_ops_list;
  int ops_count = 0;

  while (current_ops && ops_count < 10) {
    addr_t func = 0;
    addr_t next = 0;
    uint64_t flags = 0;

    vmi_read_addr_va(vmi, current_ops + LINUX_FTRACE_OPS_FUNC_OFFSET, 0, &func);
    vmi_read_addr_va(vmi, current_ops + LINUX_FTRACE_OPS_NEXT_OFFSET, 0, &next);
    vmi_read_64_va(vmi, current_ops + LINUX_FTRACE_OPS_FLAGS_OFFSET, 0, &flags);

    if (func && func != 0xffffffffffffffff) {
      if (func < kernel_start || func > kernel_end) {
        char* func_name = resolve_enclosing_symbol_pretty(vmi, func);
        const char* hook_type = "ftrace_ops";
        const char* attach_type = "ftrace_ops";

        ftrace_hooks_state_add_hook(
            data, *hook_id, hook_type, func_name ? func_name : "unknown",
            attach_type, func, "0x0", 0, 0, true,
            "Ftrace operation callback outside kernel text");

        ftrace_hooks_state_add_attachment_point(data, attach_type, *hook_id);

        if (func_name) {
          g_free(func_name);
        }

        (*hook_id)++;
        (*suspicious_count)++;
      }
    }

    current_ops = next;
    ops_count++;
  }

  log_debug(
      "Ftrace ops analysis completed: checked %d operations, found %u "
      "suspicious callbacks.",
      ops_count, *suspicious_count);
}

/**
 * @brief Detect ftrace hooks and populate the state data structure
 * 
 * Main detection function that orchestrates the ftrace hook detection process.
 * Methods used are direct memory scanning and ftrace_ops analysis.
 * 
 * @note ftrace_pages and __mcount_loc methods are currently not working due to
 * skill issue.
 * 
 * @param vmi LibVMI instance
 * @return Populated ftrace_hooks_state_data_t structure or NULL on failure
 */
static ftrace_hooks_state_data_t* detect_ftrace_hooks(vmi_instance_t vmi) {
  ftrace_hooks_state_data_t* data = ftrace_hooks_state_data_new();
  if (!data) {
    return NULL;
  }

  uint32_t suspicious_count = 0;
  uint32_t hook_id = 1;

  resolve_rootkit_targets(vmi);

  addr_t kernel_start = 0, kernel_end = 0;
  get_kernel_text_section_range(vmi, &kernel_start, &kernel_end);

  log_debug("Starting direct memory scanning method.");
  uint32_t direct_scan_hooks_before = hook_id;
  scan_for_direct_hooks(vmi, data, &hook_id, &suspicious_count);
  uint32_t direct_scan_hooks_found = hook_id - direct_scan_hooks_before;
  if (direct_scan_hooks_found > 0) {
    log_info("Direct memory scanning method SUCCESS: found %u hooks.",
             direct_scan_hooks_found);
  } else {
    log_warn("Direct memory scanning method FAILED: no hooks found.");
  }

  log_debug("Starting ftrace_ops_list analysis method.");
  uint32_t ftrace_ops_hooks_before = hook_id;
  analyze_ftrace_operations(vmi, data, kernel_start, kernel_end, &hook_id,
                            &suspicious_count);
  uint32_t ftrace_ops_hooks_found = hook_id - ftrace_ops_hooks_before;
  if (ftrace_ops_hooks_found > 0) {
    log_info("Ftrace ops analysis method SUCCESS: found %u hooks.",
             ftrace_ops_hooks_found);
  } else {
    log_warn("Ftrace ops analysis method FAILED: no hooks found.");
  }

  ftrace_hooks_state_set_summary(data, suspicious_count, suspicious_count,
                                 false, suspicious_count);

  // Final summary
  log_info("Detection summary:");
  log_info("Direct scan hooks found: %u", direct_scan_hooks_found);
  log_info("Ftrace ops hooks found: %u", ftrace_ops_hooks_found);
  log_info("Total suspicious hooks: %u", suspicious_count);

  return data;
}

uint32_t state_ftrace_hooks_callback(vmi_instance_t vmi, void* context) {
  if (!vmi || !context) {
    return log_error_and_queue_response_task(
        "ftrace_hooks_state", STATE_FTRACE_HOOKS, INVALID_ARGUMENTS,
        "STATE_FTRACE_HOOKS: Invalid arguments to ftrace hooks state callback");
  }

  event_handler_t* event_handler = (event_handler_t*)context;
  if (!event_handler || !event_handler->is_paused) {
    return log_error_and_queue_response_task(
        "ftrace_hooks_state", STATE_FTRACE_HOOKS, INVALID_ARGUMENTS,
        "STATE_FTRACE_HOOKS: Callback requires a valid event handler context");
  }

  log_info("Executing STATE_FTRACE_HOOKS callback.");

  ftrace_hooks_state_data_t* hooks_data = detect_ftrace_hooks(vmi);
  if (!hooks_data) {
    return log_error_and_queue_response_task(
        "ftrace_hooks_state", STATE_FTRACE_HOOKS, MEMORY_ALLOCATION_FAILURE,
        "STATE_FTRACE_HOOKS: Failed to allocate memory for ftrace hooks state "
        "data");
  }

  uint32_t suspicious_ops = hooks_data->summary.suspicious_hooks;

  log_info("Active hooks detected: %d", suspicious_ops);
  log_info("Total suspicious findings: %d", suspicious_ops);

  if (suspicious_ops > 0) {
    log_warn("%d active function hooks found!", suspicious_ops);
  }

  log_info("STATE_FTRACE_HOOKS callback completed.");

  return log_success_and_queue_response_task(
      "ftrace_hooks_state", STATE_FTRACE_HOOKS, hooks_data,
      (void (*)(void*))ftrace_hooks_state_data_free);
}