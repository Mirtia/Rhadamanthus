#include "state_callbacks/ftrace_hooks.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <string.h>

// Exact offsets from pahole's output for linux-5.15.0-139-generic kernel.
#define FTRACE_OPS_FUNC_OFFSET 0
#define FTRACE_OPS_NEXT_OFFSET 8
#define FTRACE_OPS_FLAGS_OFFSET 16
#define FTRACE_OPS_PRIVATE_OFFSET 24
#define FTRACE_OPS_SAVED_FUNC_OFFSET 32
#define FTRACE_OPS_FUNC_HASH_OFFSET 88
#define FTRACE_OPS_TRAMPOLINE_OFFSET 144
#define FTRACE_OPS_TRAMPOLINE_SIZE_OFFSET 152
#define FTRACE_OPS_LIST_OFFSET 160

/**
 * @brief Ftrace flags from the PoC that indicate hooking
 */
#define FTRACE_OPS_FL_SAVE_REGS (1 << 1)
#define FTRACE_OPS_FL_RECURSION (1 << 13)
#define FTRACE_OPS_FL_IPMODIFY (1 << 12)

// Hooking signature: SAVE_REGS | RECURSION | IPMODIFY
#define HOOKING_FLAGS_SIGNATURE \
  (FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY)

/**
 * @brief Common syscalls that are frequently hooked (from the PoC)
 */
static const char* commonly_hooked_syscalls[] = {
    "__x64_sys_clone",       // From the PoC
    "__x64_sys_execve",      // From the PoC
    "__x64_sys_openat",      // Commonly targeted
    "__x64_sys_read",        // File operations
    "__x64_sys_write",       // File operations
    "__x64_sys_getdents64",  // Directory hiding
    "__x64_sys_kill",        // Process hiding
    "sys_clone",             // Legacy naming
    "sys_execve",            // Legacy naming
    NULL};

/**
 * @brief Check if ftrace flags indicate malicious hooking
 *
 * @param flags Ftrace operation flags
 * @return true if suspicious flags detected
 */
static bool is_hooking_flags_pattern(unsigned long flags) {
  // The PoC uses exactly this combination for IP modification
  if ((flags & HOOKING_FLAGS_SIGNATURE) == HOOKING_FLAGS_SIGNATURE) {
    return true;
  }

  // IPMODIFY without SAVE_REGS is also suspicious
  if ((flags & FTRACE_OPS_FL_IPMODIFY) && !(flags & FTRACE_OPS_FL_SAVE_REGS)) {
    return true;
  }

  return false;
}

/**
 * @brief Analyze a single ftrace_ops structure for hooking patterns
 *
 * @param vmi LibVMI instance
 * @param ops_addr Address of ftrace_ops structure
 * @param ops_num Operation number for logging
 * @param kernel_start Start of kernel text section
 * @param kernel_end End of kernel text section
 * @return true if hooking pattern detected
 */
static bool analyze_ftrace_ops_for_hooks(vmi_instance_t vmi, addr_t ops_addr,
                                         // NOLINTNEXTLINE
                                         int ops_num, addr_t kernel_start,
                                         addr_t kernel_end) {
  // Read ftrace function pointer (offset 0)
  addr_t func_addr = 0;
  if (vmi_read_addr_va(vmi, ops_addr + FTRACE_OPS_FUNC_OFFSET, 0, &func_addr) !=
      VMI_SUCCESS) {
    log_warn("Failed to read ftrace func at 0x%" PRIx64,
             ops_addr + FTRACE_OPS_FUNC_OFFSET);
    return false;
  }

  // Read flags (offset 16)
  unsigned long flags = 0;
  if (vmi_read_64_va(vmi, ops_addr + FTRACE_OPS_FLAGS_OFFSET, 0, &flags) !=
      VMI_SUCCESS) {
    log_warn("Failed to read ftrace flags at 0x%" PRIx64,
             ops_addr + FTRACE_OPS_FLAGS_OFFSET);
    return false;
  }

  // Read trampoline address (offset 144) - this is often used in hooks
  addr_t trampoline_addr = 0;
  vmi_read_addr_va(vmi, ops_addr + FTRACE_OPS_TRAMPOLINE_OFFSET, 0,
                   &trampoline_addr);

  // Read saved_func (offset 32) - original function before hooking
  addr_t saved_func = 0;
  vmi_read_addr_va(vmi, ops_addr + FTRACE_OPS_SAVED_FUNC_OFFSET, 0,
                   &saved_func);

  log_info("Ftrace Operation %d [0x%" PRIx64 "]:", ops_num, (uint64_t)ops_addr);
  log_info("  Function: 0x%" PRIx64, (uint64_t)func_addr);
  log_info("  Flags: 0x%lx", flags);
  if (trampoline_addr != 0) {
    log_info("  Trampoline: 0x%" PRIx64, (uint64_t)trampoline_addr);
  }
  if (saved_func != 0) {
    log_info("  Saved Function: 0x%" PRIx64, (uint64_t)saved_func);
  }

  bool suspicious = false;

  // Check for hooking flag pattern (like in the PoC)
  if (is_hooking_flags_pattern(flags)) {
    log_warn(
        "  HOOK DETECTED: Flags match hooking pattern "
        "(SAVE_REGS|RECURSION|IPMODIFY)");
    suspicious = true;
  }

  // Check if function is outside kernel text (indicates module hooking)
  if (func_addr < kernel_start || func_addr > kernel_end) {
    log_warn("  HOOK DETECTED: Function 0x%" PRIx64
             " is outside kernel text (likely module)",
             (uint64_t)func_addr);
    suspicious = true;
  }

  // Check trampoline legitimacy
  if (trampoline_addr != 0 &&
      (trampoline_addr < kernel_start || trampoline_addr > kernel_end)) {
    log_warn("  HOOK DETECTED: Trampoline 0x%" PRIx64 " is outside kernel text",
             (uint64_t)trampoline_addr);
    suspicious = true;
  }

  // Check for the specific thunk pattern from the PoC
  if (flags & FTRACE_OPS_FL_IPMODIFY) {
    log_warn(
        "  HOOK DETECTED: Function modifies instruction pointer (IPMODIFY "
        "flag)");
    suspicious = true;
  }

  // If we have both original and hook functions, that's very suspicious
  if (saved_func != 0 && func_addr != 0 && saved_func != func_addr) {
    log_warn(
        "  HOOK DETECTED: Different function and saved_func addresses (clear "
        "hooking)");
    suspicious = true;
  }

  return suspicious;
}

/**
 * @brief Check if any commonly targeted syscalls are being traced
 *
 * @param vmi LibVMI instance
 * @return Number of hooked syscalls detected
 */
static int check_commonly_hooked_syscalls(vmi_instance_t vmi) {
  int hooked_count = 0;

  log_info("Checking if commonly targeted syscalls have active ftrace...");

  for (int i = 0; commonly_hooked_syscalls[i] != NULL; i++) {
    addr_t syscall_addr = 0;

    // Try to resolve the syscall address
    if (vmi_translate_ksym2v(vmi, commonly_hooked_syscalls[i], &syscall_addr) ==
        VMI_SUCCESS) {
      log_info("Found syscall %s at 0x%" PRIx64, commonly_hooked_syscalls[i],
               (uint64_t)syscall_addr);

      // TODO: Check if this specific function has ftrace enabled.
      // This would require walking the ftrace filter hash tables, which is complex
      // For now, we just log that we found these common targets.
    }
  }

  return hooked_count;
}

/**
 * @brief Walk the global ftrace_ops_list to find active hooks
 *
 * @param vmi LibVMI instance
 * @param kernel_start Start of kernel text section
 * @param kernel_end End of kernel text section
 * @return Number of suspicious ftrace operations found
 */
static int walk_ftrace_ops_list(vmi_instance_t vmi, addr_t kernel_start,
                                addr_t kernel_end) {
  addr_t ftrace_ops_list_addr = 0;

  // Try to find the global ftrace ops list
  if (vmi_translate_ksym2v(vmi, "ftrace_ops_list", &ftrace_ops_list_addr) !=
      VMI_SUCCESS) {
    log_warn("Failed to resolve ftrace_ops_list - trying alternative symbols");

    // Try alternative symbol names
    if (vmi_translate_ksym2v(vmi, "ftrace_global_list",
                             &ftrace_ops_list_addr) != VMI_SUCCESS) {
      log_error("Could not find ftrace operations list");
      return 0;
    }
  }

  log_info("Found ftrace_ops_list at: 0x%" PRIx64,
           (uint64_t)ftrace_ops_list_addr);

  // Read the first ftrace_ops pointer
  addr_t current_ops = 0;
  if (vmi_read_addr_va(vmi, ftrace_ops_list_addr, 0, &current_ops) !=
      VMI_SUCCESS) {
    log_error("Failed to read first ftrace_ops pointer");
    return 0;
  }

  if (current_ops == 0) {
    log_info("No active ftrace operations found");
    return 0;
  }

  int suspicious_count = 0;
  int ops_count = 0;
  addr_t first_ops = current_ops;

  log_info("Walking ftrace operations list starting at 0x%" PRIx64,
           (uint64_t)current_ops);

  // Walk the linked list of ftrace_ops
  do {
    ops_count++;

    if (analyze_ftrace_ops_for_hooks(vmi, current_ops, ops_count, kernel_start,
                                     kernel_end)) {
      suspicious_count++;
    }

    // Read next pointer
    addr_t next_ops = 0;
    if (vmi_read_addr_va(vmi, current_ops + FTRACE_OPS_NEXT_OFFSET, 0,
                         &next_ops) != VMI_SUCCESS) {
      log_warn("Failed to read next ftrace_ops pointer");
      break;
    }

    current_ops = next_ops;

    // Prevent infinite loops
    if (current_ops == first_ops || ops_count > 100) {
      break;
    }

  } while (current_ops != 0);

  log_info("Analyzed %d ftrace operations, %d suspicious", ops_count,
           suspicious_count);
  return suspicious_count;
}

/**
 * @brief Check global ftrace state for signs of active hooking
 *
 * @param vmi LibVMI instance
 * @return Number of suspicious global state indicators
 */
static int check_ftrace_global_state(vmi_instance_t vmi) {
  int suspicious = 0;

  // Check if ftrace is globally enabled
  addr_t ftrace_enabled_addr = 0;
  if (vmi_translate_ksym2v(vmi, "ftrace_enabled", &ftrace_enabled_addr) ==
      VMI_SUCCESS) {
    uint32_t enabled = 0;
    if (vmi_read_32_va(vmi, ftrace_enabled_addr, 0, &enabled) == VMI_SUCCESS) {
      log_info("Global ftrace enabled: %s", enabled ? "YES" : "NO");

      if (enabled) {
        log_info("Ftrace is active - checking for malicious usage...");
      } else {
        log_info("Ftrace is disabled globally");
      }
    }
  }

  return suspicious;
}

uint32_t state_ftrace_hooks_callback(vmi_instance_t vmi, void* context) {
  (void)context;

  // Get kernel text bounds for validation
  addr_t kernel_start = 0, kernel_end = 0;
  if (vmi_translate_ksym2v(vmi, "_stext", &kernel_start) != VMI_SUCCESS ||
      vmi_translate_ksym2v(vmi, "_etext", &kernel_end) != VMI_SUCCESS) {
    log_error("Failed to resolve kernel text boundaries");
    return VMI_FAILURE;
  }

  log_info("Kernel text section: [0x%" PRIx64 " - 0x%" PRIx64 "]",
           (uint64_t)kernel_start, (uint64_t)kernel_end);

  // Check global ftrace state
  log_info("=== Checking Global Ftrace State ===");
  int global_issues = check_ftrace_global_state(vmi);

  // Check for commonly hooked syscalls
  log_info("=== Checking Commonly Targeted Syscalls ===");
  int syscall_issues = check_commonly_hooked_syscalls(vmi);

  // Walk ftrace operations list for active hooks
  log_info("=== Analyzing Active Ftrace Operations ===");
  int hook_detections = walk_ftrace_ops_list(vmi, kernel_start, kernel_end);

  // Summary
  int total_issues = global_issues + syscall_issues + hook_detections;
  log_info("=== FTRACE HOOK DETECTION SUMMARY ===");
  log_info("Global ftrace issues: %d", global_issues);
  log_info("Syscall-related issues: %d", syscall_issues);
  log_info("Active hooks detected: %d", hook_detections);
  log_info("Total suspicious findings: %d", total_issues);

  if (hook_detections > 0) {
    log_warn("FTRACE HOOKS DETECTED: %d active function hooks found!",
             hook_detections);
  } else if (total_issues > 0) {
    log_warn("FTRACE ANOMALIES: %d suspicious findings", total_issues);
  } else {
    log_info("No ftrace-based hooks detected");
  }

  log_info("STATE_FTRACE_HOOKS callback completed.");
  return VMI_SUCCESS;
}