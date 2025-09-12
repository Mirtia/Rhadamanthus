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
#define ROOTKIT_MODULE_START 0xffffffffc0000000
#define ROOTKIT_MODULE_END 0xffffffffc0ffffff

typedef struct {
  const char* symbol_name;
  addr_t* addr_ptr;
} rootkit_target_t;

/**
 * @brief Check if an address is in the kernel virtual address space
 * 
 * @details On x86-64 Linux, the kernel is mapped in the canonical high half (upper 2^47
 * addresses). KASLR randomizes the base address within this range, but the MSB
 * always remains 1 due to canonical addressing requirements.
 * See: https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
 *
 * @param virtual_addr The virtual address to check
 * @return true if the address is in kernel space, false otherwise
 */
static inline bool is_kernel_va_x86_64(addr_t virtual_addr) {
  return (virtual_addr >> 63) == 1ULL;
}

/**
 * @brief Check if an address is likely in kernel text section
 * 
 * @details Validates that an address falls within the kernel's .text section boundaries.
 * Also performs a heuristic check for module text sections which typically
 * reside in the kernel high half address space.
 * 
 * @param virtual_addr The virtual address to check
 * @param ktext_start Start of kernel text section
 * @param ktext_end End of kernel text section
 * @return true if the address is likely in kernel text, false otherwise
 */
static inline bool is_probably_kernel_text(addr_t virtual_addr,
                                           addr_t ktext_start,
                                           addr_t ktext_end) {
  if (virtual_addr >= ktext_start && virtual_addr < ktext_end)
    return true;
  return is_kernel_va_x86_64(virtual_addr);
}

/**
 * @brief Classify the state of an ftrace call site by examining bytes
 * 
 * @details Examines the first 5 bytes at the given address to determine if it's an active
 * ftrace call site (0xE8 CALL instruction) or a disabled site (5-byte NOP).
 * When ftrace is enabled, the compiler-inserted __fentry__ call sites are patched
 * with CALL instructions. When disabled, they're replaced with 5-byte NOPs.
 * The specific NOP pattern 0F 1F 44 00 00 is the standard 5-byte NOP on x86-64.
 * See: https://www.brendangregg.com/blog/2019-10-15/kernelrecipes-kernel-ftrace-internals.html
 * See: https://www.kernel.org/doc/Documentation/trace/ftrace.txt
 *
 * @param vmi LibVMI instance
 * @param address The address to examine
 * @return String describing the site state: "CALL(__fentry__)", "NOP5", "other", or "unreadable"
 */
static const char* classify_fentry_site(vmi_instance_t vmi, addr_t address) {
  uint8_t bytes[5] = {0};
  if (vmi_read_8_va(vmi, address + 0, 0, &bytes[0]) != VMI_SUCCESS)
    return "unreadable";

  if (bytes[0] == 0xE8) {
    return "CALL(__fentry__)";
  }
  if (vmi_read_8_va(vmi, address + 1, 0, &bytes[1]) == VMI_SUCCESS &&
      vmi_read_8_va(vmi, address + 2, 0, &bytes[2]) == VMI_SUCCESS &&
      vmi_read_8_va(vmi, address + 3, 0, &bytes[3]) == VMI_SUCCESS &&
      vmi_read_8_va(vmi, address + 4, 0, &bytes[4]) == VMI_SUCCESS &&
      bytes[0] == 0x0F && bytes[1] == 0x1F && bytes[2] == 0x44 &&
      bytes[3] == 0x00 && bytes[4] == 0x00) {
    return "NOP5";
  }

  return "other";
}

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
 * @brief Check if a call site matches any known rootkit target functions
 * 
 * @details Resolves the call site address to a function name and checks if it matches
 * any of the known rootkit target functions. This targets functions commonly
 * hooked by rootkits for hiding processes, network connections, files, and
 * system calls. The function extracts the base function name (removing +offset) for comparison
 * against the known targets list, which includes network stack functions,
 * syscalls, and process management functions.
 * 
 * @param vmi LibVMI instance
 * @param call_site_addr Address of the call site to check
 * @return Function name with offset if match found, NULL otherwise.
 *         Caller must free with g_free().
 */
static char* check_rootkit_target_match(vmi_instance_t vmi,
                                        addr_t call_site_addr) {
  char* function_name = resolve_enclosing_symbol_pretty(vmi, call_site_addr);
  if (!function_name) {
    return NULL;
  }

  char* base_name = g_strdup(function_name);
  char* plus_pos = strchr(base_name, '+');
  if (plus_pos) {
    *plus_pos = '\0';
  }
  for (int i = 0; known_rootkit_targets[i].symbol_name != NULL; i++) {
    if (strcmp(base_name, known_rootkit_targets[i].symbol_name) == 0) {
      g_free(base_name);
      return function_name;  // Return with offset
    }
  }

  g_free(base_name);
  g_free(function_name);
  return NULL;
}

/**
 * @brief Enumerate call-site IPs from dyn_ftrace records via ftrace_pages
 * 
 * @details This is the authoritative runtime source for ftrace call sites. Walks the
 * ftrace_pages linked list to enumerate all dyn_ftrace records and collect
 * their call site addresses. The ftrace_pages structure contains a linked list of pages, each containing
 * an array of dyn_ftrace records. Each record contains the call site IP and
 * flags indicating the current state of the ftrace instrumentation.
 * 
 * @see include/linux/ftrace.h for struct ftrace_page and dyn_ftrace definitions
 * @param vmi LibVMI instance
 * @param ftrace_pages_addr Address of ftrace_pages_start
 * @param target_functions GSList to collect target function addresses
 * @return Number of call sites found
 */
static size_t enumerate_dyn_ftrace_sites(vmi_instance_t vmi,
                                         addr_t ftrace_pages_addr,
                                         GSList** target_functions) {
  size_t total_sites = 0;

  if (!ftrace_pages_addr) {
    log_debug(
        "FTRACE_DETECTION: enumerate_dyn_ftrace_sites - ftrace_pages_addr is "
        "NULL");
    return 0;
  }

  log_debug(
      "FTRACE_DETECTION: enumerate_dyn_ftrace_sites - starting at 0x%" PRIx64,
      (uint64_t)ftrace_pages_addr);

  addr_t current_page = ftrace_pages_addr;
  for (int page_count = 0; current_page && page_count < MAX_FTRACE_PAGES;
       page_count++) {
    addr_t next_page = 0;
    addr_t records = 0;
    uint32_t index = 0;
    uint32_t order = 0;
    uint32_t size = 0;

    vmi_read_addr_va(vmi, current_page + FTRACE_PAGE_NEXT_OFF, 0, &next_page);
    vmi_read_addr_va(vmi, current_page + FTRACE_PAGE_RECORDS_OFF, 0, &records);
    vmi_read_32_va(vmi, current_page + FTRACE_PAGE_INDEX_OFF, 0, &index);
    vmi_read_32_va(vmi, current_page + FTRACE_PAGE_ORDER_OFF, 0, &order);
    vmi_read_32_va(vmi, current_page + FTRACE_PAGE_SIZE_OFF, 0, &size);

    if (!records || !size || index > size || size > 8192) {
      log_debug(
          "FTRACE_DETECTION: enumerate_dyn_ftrace_sites - page %d invalid: "
          "records=0x%" PRIx64 " size=%u index=%u",
          page_count, (uint64_t)records, size, index);
      break;
    }

    log_debug(
        "FTRACE_DETECTION: enumerate_dyn_ftrace_sites - processing page %d: "
        "records=0x%" PRIx64 " size=%u",
        page_count, (uint64_t)records, size);
    const size_t rec_stride = 0x10;
    for (uint32_t i = 0; i < size && i < 1024; i++) {
      addr_t rec = records + i * rec_stride;
      addr_t call_site_ip = 0;
      uint64_t flags = 0;

      if (vmi_read_addr_va(vmi, rec + DYN_FTRACE_IP_OFF, 0, &call_site_ip) !=
              VMI_SUCCESS ||
          vmi_read_64_va(vmi, rec + DYN_FTRACE_FLAGS_OFF, 0, &flags) !=
              VMI_SUCCESS) {
        continue;
      }

      if (!call_site_ip || !is_kernel_va_x86_64(call_site_ip)) {
        continue;
      }

      *target_functions =
          g_slist_prepend(*target_functions, GSIZE_TO_POINTER(call_site_ip));
      total_sites++;
    }

    current_page = next_page;
  }

  log_debug(
      "FTRACE_DETECTION: enumerate_dyn_ftrace_sites - completed, found %zu "
      "total sites",
      total_sites);
  return total_sites;
}

/**
 * @brief Enumerate call-site IPs from __mcount_loc table (fallback)
 * 
 * @details This is a build-time table that may not be available post-boot or may be
 * corrupted. Used as a fallback when ftrace_pages enumeration fails.
 * The __mcount_loc section contains virtual addresses of all __fentry__ call
 * sites inserted by the compiler. This table is created at build time and
 * may be removed or corrupted by rootkits to hide their hooks.
 * 
 * @see https://www.kernel.org/doc/Documentation/trace/ftrace.txt
 * @param vmi LibVMI instance
 * @param target_functions GSList to collect target function addresses
 * @return Number of call sites found
 */
static size_t enumerate_mcount_loc_sites(vmi_instance_t vmi,
                                         GSList** target_functions) {
  size_t total_sites = 0;
  addr_t start_mcount_loc = 0;
  addr_t stop_mcount_loc = 0;

  log_debug(
      "FTRACE_DETECTION: enumerate_mcount_loc_sites - attempting to resolve "
      "__start_mcount_loc and __stop_mcount_loc");

  if (vmi_translate_ksym2v(vmi, "__start_mcount_loc", &start_mcount_loc) !=
          VMI_SUCCESS ||
      vmi_translate_ksym2v(vmi, "__stop_mcount_loc", &stop_mcount_loc) !=
          VMI_SUCCESS) {
    log_debug(
        "FTRACE_DETECTION: enumerate_mcount_loc_sites - FAILED to resolve "
        "__start_mcount_loc or __stop_mcount_loc symbols");
    return 0;
  }

  log_debug(
      "FTRACE_DETECTION: enumerate_mcount_loc_sites - resolved symbols: "
      "start=0x%" PRIx64 " stop=0x%" PRIx64,
      (uint64_t)start_mcount_loc, (uint64_t)stop_mcount_loc);

  if (stop_mcount_loc <= start_mcount_loc) {
    log_debug(
        "FTRACE_DETECTION: enumerate_mcount_loc_sites - invalid range: stop <= "
        "start");
    return 0;
  }

  size_t mcount_loc_size = stop_mcount_loc - start_mcount_loc;
  size_t num_entries = mcount_loc_size / sizeof(addr_t);
  size_t max_entries =
      (num_entries < MAX_MCOUNT_ENTRIES) ? num_entries : MAX_MCOUNT_ENTRIES;

  log_debug(
      "FTRACE_DETECTION: enumerate_mcount_loc_sites - processing %zu entries "
      "(size=%zu, max=%zu)",
      num_entries, mcount_loc_size, max_entries);

  for (size_t i = 0; i < max_entries; i++) {
    addr_t entry_addr = start_mcount_loc + (i * sizeof(addr_t));
    addr_t call_site_addr = 0;

    if (vmi_read_addr_va(vmi, entry_addr, 0, &call_site_addr) != VMI_SUCCESS ||
        call_site_addr == 0) {
      continue;
    }

    if (!is_kernel_va_x86_64(call_site_addr)) {
      continue;
    }

    *target_functions =
        g_slist_prepend(*target_functions, GSIZE_TO_POINTER(call_site_addr));
    total_sites++;
  }

  log_debug(
      "FTRACE_DETECTION: enumerate_mcount_loc_sites - completed, found %zu "
      "total sites",
      total_sites);
  return total_sites;
}

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
 * Analyzes the function name and other characteristics to determine the most
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

  return "fentry";  // Default to fentry for general function hooks
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
  log_debug(
      "FTRACE_DETECTION: scan_for_direct_hooks - starting direct memory scan "
      "of known rootkit targets");
  int targets_checked = 0;
  int targets_with_addresses = 0;

  for (int j = 0; known_rootkit_targets[j].symbol_name != NULL; j++) {
    targets_checked++;
    if (known_rootkit_targets[j].addr_ptr) {
      targets_with_addresses++;
      addr_t target_addr = *(known_rootkit_targets[j].addr_ptr);

      for (addr_t check_addr = target_addr; check_addr < target_addr + 0x40;
           check_addr++) {
        uint8_t byte1 = 0;
        if (vmi_read_8_va(vmi, check_addr, 0, &byte1) == VMI_SUCCESS &&
            byte1 == 0xE8) {
          uint32_t call_offset = 0;
          if (vmi_read_32_va(vmi, check_addr + 1, 0, &call_offset) ==
              VMI_SUCCESS) {
            addr_t call_target = check_addr + 5 + call_offset;

            if (call_target >= ROOTKIT_MODULE_START &&
                call_target <= ROOTKIT_MODULE_END) {

              // Determine attachment type and hook type
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

              // Add to attachment points
              ftrace_hooks_state_add_attachment_point(data, attach_type,
                                                      *hook_id);

              (*hook_id)++;
              (*suspicious_count)++;
              log_debug(
                  "FTRACE_DETECTION: scan_for_direct_hooks - found hook in %s "
                  "at 0x%" PRIx64 " -> 0x%" PRIx64,
                  known_rootkit_targets[j].symbol_name, (uint64_t)check_addr,
                  (uint64_t)call_target);
              break;
            }
          }
        }
      }
    }
  }

  log_debug(
      "FTRACE_DETECTION: scan_for_direct_hooks - completed: checked %d "
      "targets, %d had addresses, found %u hooks",
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
  log_debug(
      "FTRACE_DETECTION: analyze_ftrace_operations - attempting to resolve "
      "ftrace_ops_list symbol");

  if (vmi_translate_ksym2v(vmi, "ftrace_ops_list", &ftrace_ops_list) !=
      VMI_SUCCESS) {
    log_debug(
        "FTRACE_DETECTION: analyze_ftrace_operations - FAILED to resolve "
        "ftrace_ops_list symbol");
    return;
  }

  log_debug(
      "FTRACE_DETECTION: analyze_ftrace_operations - resolved ftrace_ops_list "
      "at 0x%" PRIx64,
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
        // This is a suspicious ftrace operation with callback outside kernel text
        char* func_name = resolve_enclosing_symbol_pretty(vmi, func);
        const char* hook_type = "ftrace_ops";
        const char* attach_type = "ftrace_ops";

        ftrace_hooks_state_add_hook(
            data, *hook_id, hook_type, func_name ? func_name : "unknown",
            attach_type, func, "0x0", 0, 0, true,
            "Ftrace operation callback outside kernel text");

        // Add to attachment points
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
      "FTRACE_DETECTION: analyze_ftrace_operations - completed: checked %d "
      "operations, found %u suspicious callbacks",
      ops_count, *suspicious_count);
}

/**
 * @brief Detect ftrace hooks and populate the state data structure
 * 
 * Main detection function that orchestrates the ftrace hook detection process.
 * Uses multiple detection methods: ftrace_pages enumeration, __mcount_loc fallback,
 * direct memory scanning of known rootkit targets, and ftrace_ops analysis.
 * 
 * The detection process follows a layered approach:
 * * Resolve known rootkit target function addresses
 * * Perform direct memory scanning for CALL instructions in target functions (WORKING)
 * * Analyze ftrace_ops_list for suspicious callback functions (WORKING)
 * 
 * NOTE: ftrace_pages and __mcount_loc methods are currently disabled due to
 * skill issue.
 * 
 * Each detected hook is classified by attachment type (syscall, network, filesystem,
 * process, fentry, ftrace_ops) and hook type (ftrace_hook, syscall_hook, etc.)
 * based on the function name and detection method.
 * 
 * This multi-method approach ensures detection even when rootkits corrupt
 * kernel data structures to hide their hooks.
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
  GSList* target_functions = NULL;

  resolve_rootkit_targets(vmi);

  addr_t kernel_start = 0, kernel_end = 0;
  get_kernel_text_section_range(vmi, &kernel_start, &kernel_end);

  // TODO: INVESTIGATE - ftrace_pages method is not working
  // Issue: Data structure appears corrupted (records=0x0, invalid index values)
  // This method consistently fails to find valid call sites
  /*
  addr_t ftrace_pages_start = 0;
  if (vmi_translate_ksym2v(vmi, "ftrace_pages_start", &ftrace_pages_start) ==
      VMI_SUCCESS) {
    log_debug(
        "FTRACE_DETECTION: Attempting ftrace_pages enumeration at 0x%" PRIx64,
        (uint64_t)ftrace_pages_start);
    size_t ftrace_pages_count =
        enumerate_dyn_ftrace_sites(vmi, ftrace_pages_start, &target_functions);
    log_debug("FTRACE_DETECTION: ftrace_pages method found %zu call sites",
              ftrace_pages_count);
    if (ftrace_pages_count > 0) {
      log_info(
          "FTRACE_DETECTION: ftrace_pages method SUCCESS - found %zu call "
          "sites",
          ftrace_pages_count);
    } else {
      log_warn(
          "FTRACE_DETECTION: ftrace_pages method FAILED - no call sites found");
    }
  } else {
    log_warn(
        "FTRACE_DETECTION: ftrace_pages method FAILED - could not resolve "
        "ftrace_pages_start symbol");
  }
  */

  // TODO: INVESTIGATE - __mcount_loc method is not working
  // Issue: Finds 50,319+ entries but 0 valid call sites (likely corrupted by rootkit)
  // This method consistently fails to find valid call sites
  /*
  if (g_slist_length(target_functions) == 0) {
    log_debug("FTRACE_DETECTION: Attempting __mcount_loc fallback method");
    size_t mcount_loc_count =
        enumerate_mcount_loc_sites(vmi, &target_functions);
    log_debug("FTRACE_DETECTION: __mcount_loc method found %zu call sites",
              mcount_loc_count);
    if (mcount_loc_count > 0) {
      log_info(
          "FTRACE_DETECTION: __mcount_loc method SUCCESS - found %zu call "
          "sites",
          mcount_loc_count);
    } else {
      log_warn(
          "FTRACE_DETECTION: __mcount_loc method FAILED - no call sites found");
    }
  } else {
    log_info(
        "FTRACE_DETECTION: Skipping __mcount_loc method - ftrace_pages already "
        "found %d sites",
        (int)g_slist_length(target_functions));
  }
  */

  log_debug(
      "FTRACE_DETECTION: Checking %d target functions for rootkit matches",
      (int)g_slist_length(target_functions));
  int rootkit_matches = 0;
  GSList* iter = target_functions;
  while (iter) {
    addr_t call_site = GPOINTER_TO_SIZE(iter->data);
    char* match = check_rootkit_target_match(vmi, call_site);
    if (match) {
      rootkit_matches++;
      log_debug("FTRACE_DETECTION: Found rootkit target match: %s", match);
      g_free(match);
    }
    iter = iter->next;
  }
  log_info(
      "FTRACE_DETECTION: Target function matching found %d rootkit matches",
      rootkit_matches);

  log_debug("FTRACE_DETECTION: Starting direct memory scanning method");
  uint32_t direct_scan_hooks_before = hook_id;
  scan_for_direct_hooks(vmi, data, &hook_id, &suspicious_count);
  uint32_t direct_scan_hooks_found = hook_id - direct_scan_hooks_before;
  if (direct_scan_hooks_found > 0) {
    log_info(
        "FTRACE_DETECTION: Direct memory scanning method SUCCESS - found %u "
        "hooks",
        direct_scan_hooks_found);
  } else {
    log_warn(
        "FTRACE_DETECTION: Direct memory scanning method FAILED - no hooks "
        "found");
  }

  log_debug("FTRACE_DETECTION: Starting ftrace_ops_list analysis method");
  uint32_t ftrace_ops_hooks_before = hook_id;
  analyze_ftrace_operations(vmi, data, kernel_start, kernel_end, &hook_id,
                            &suspicious_count);
  uint32_t ftrace_ops_hooks_found = hook_id - ftrace_ops_hooks_before;
  if (ftrace_ops_hooks_found > 0) {
    log_info(
        "FTRACE_DETECTION: ftrace_ops_list analysis method SUCCESS - found %u "
        "hooks",
        ftrace_ops_hooks_found);
  } else {
    log_warn(
        "FTRACE_DETECTION: ftrace_ops_list analysis method FAILED - no hooks "
        "found");
  }

  ftrace_hooks_state_set_summary(data, suspicious_count, suspicious_count,
                                 false, suspicious_count);

  // Final summary
  log_info("FTRACE_DETECTION: Detection summary:");
  log_info("FTRACE_DETECTION: - Total target functions found: %d",
           (int)g_slist_length(target_functions));
  log_info("FTRACE_DETECTION: - Rootkit target matches: %d", rootkit_matches);
  log_info("FTRACE_DETECTION: - Direct scan hooks found: %u",
           direct_scan_hooks_found);
  log_info("FTRACE_DETECTION: - Ftrace ops hooks found: %u",
           ftrace_ops_hooks_found);
  log_info("FTRACE_DETECTION: - Total suspicious hooks: %u", suspicious_count);

  g_slist_free_full(target_functions, NULL);

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

  log_info("STATE_FTRACE_HOOKS: Active hooks detected: %d", suspicious_ops);
  log_info("STATE_FTRACE_HOOKS: Total suspicious findings: %d", suspicious_ops);

  if (suspicious_ops > 0) {
    log_warn("STATE_FTRACE_HOOKS: %d active function hooks found!",
             suspicious_ops);
  }

  log_info("STATE_FTRACE_HOOKS callback completed.");

  return log_success_and_queue_response_task(
      "ftrace_hooks_state", STATE_FTRACE_HOOKS, hooks_data,
      (void (*)(void*))ftrace_hooks_state_data_free);
}