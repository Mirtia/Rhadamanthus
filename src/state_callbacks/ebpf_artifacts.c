#include "state_callbacks/ebpf_artifacts.h"
#include <ctype.h>
#include <log.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Structure to track eBPF program metadata
typedef struct {
  uint32_t id;
  uint32_t type;
  char name[64];
  uint64_t load_time;
  uint32_t map_ids[16];
  uint32_t map_count;
  uint32_t jited;
  uint32_t tag[8];
} ebpf_prog_info_t;

// Structure to track eBPF map metadata
typedef struct {
  uint32_t id;
  uint32_t type;
  char name[64];
  uint32_t key_size;
  uint32_t value_size;
  uint32_t max_entries;
  uint32_t flags;
} ebpf_map_info_t;

// Detection context
typedef struct {
  ebpf_prog_info_t* programs;
  uint32_t prog_count;
  uint32_t prog_capacity;
  ebpf_map_info_t* maps;
  uint32_t map_count;
  uint32_t map_capacity;
  uint32_t suspicious_flags;
} ebpf_detection_ctx_t;

// Suspicious pattern flags
#define EBPF_SUSPICIOUS_HIDDEN_PROG 0x0001
#define EBPF_SUSPICIOUS_KPROBE_SYSCALL 0x0002
#define EBPF_SUSPICIOUS_XDP_BACKDOOR 0x0004
#define EBPF_SUSPICIOUS_TC_HIJACK 0x0008
#define EBPF_SUSPICIOUS_TRACEPOINT_HOOK 0x0010
#define EBPF_SUSPICIOUS_MAP_OVERFLOW 0x0020
#define EBPF_SUSPICIOUS_BTF_TAMPERING 0x0040
#define EBPF_SUSPICIOUS_OBFUSCATED_NAME 0x0080
#define EBPF_SUSPICIOUS_PINNED_PERSIST 0x0100
#define EBPF_SUSPICIOUS_GETDENTS_HOOK 0x0200

// Known rootkit signatures
static const char* known_rootkit_names[] = {"ebpfkit", "triplecross", "bpfdoor",
                                            "badbpf",  "exechijack",  "pidhide",
                                            "sudoadd", "textreplace", NULL};

// Suspicious syscall hooks commonly used by rootkits
static const char* suspicious_syscalls[] = {"sys_getdents",
                                            "sys_getdents64",
                                            "sys_kill",
                                            "sys_openat",
                                            "sys_read",
                                            "sys_write",
                                            "sys_execve",
                                            "sys_ptrace",
                                            "sys_bpf",
                                            "sys_perf_event_open",
                                            "sys_timerfd_settime",
                                            NULL};

// Static context for state comparison between calls
static ebpf_detection_ctx_t previous_ctx = {0};
static int first_run = 1;

/**
 * Initialize detection context
 */
static void init_detection_context(ebpf_detection_ctx_t* ctx) {
  ctx->prog_capacity = 256;
  ctx->map_capacity = 512;
  ctx->programs = calloc(ctx->prog_capacity, sizeof(ebpf_prog_info_t));
  ctx->maps = calloc(ctx->map_capacity, sizeof(ebpf_map_info_t));
  ctx->prog_count = 0;
  ctx->map_count = 0;
  ctx->suspicious_flags = 0;
}

/**
 * Clean up detection context
 */
static void cleanup_detection_context(ebpf_detection_ctx_t* ctx) {
  if (ctx->programs) {
    free(ctx->programs);
    ctx->programs = NULL;
  }
  if (ctx->maps) {
    free(ctx->maps);
    ctx->maps = NULL;
  }
}

/**
 * Check if a program name matches known rootkit patterns
 */
static int check_known_rootkit_signature(const char* name) {
  if (!name)
    return 0;

  for (int i = 0; known_rootkit_names[i]; i++) {
    if (strstr(name, known_rootkit_names[i])) {
      log_warn("Detected known rootkit signature: %s", name);
      return 1;
    }
  }
  return 0;
}

/**
 * Check for obfuscated or suspicious program names
 */
static int check_obfuscated_name(const char* name) {
  if (!name || strlen(name) == 0) {
    return 1;  // Empty name is suspicious
  }

  // Check for random-looking names (high entropy)
  int non_alnum = 0;
  int len = (int)strlen(name);

  for (int i = 0; i < len; i++) {
    if (!isalnum(name[i]) && name[i] != '_' && name[i] != '-') {
      non_alnum++;
    }
  }

  // If more than 30% non-alphanumeric, consider suspicious
  return (non_alnum > len * 0.3) ? 1 : 0;
}

/**
 * Enumerate eBPF programs from kernel structures
 */
static int enumerate_ebpf_programs(vmi_instance_t vmi,
                                   // NOLINTNEXTLINE
                                   ebpf_detection_ctx_t* ctx) {
  addr_t prog_idr_addr;

  log_debug("Enumerating eBPF programs from kernel structures");

  // Try to find prog_idr symbol
  if (vmi_translate_ksym2v(vmi, "prog_idr", &prog_idr_addr) != VMI_SUCCESS) {
    // Try alternative symbol names
    if (vmi_translate_ksym2v(vmi, "prog_array", &prog_idr_addr) !=
        VMI_SUCCESS) {
      log_warn("Cannot locate eBPF program tracking structures");
      return VMI_FAILURE;
    }
  }

  // TODO: Implement actual IDR/radix tree walking
  // For now, we simulate finding some programs for demonstration
  // In production, this would walk the actual kernel data structures

  log_debug("Found prog_idr at 0x%lx", prog_idr_addr);

  // Placeholder: In real implementation, walk the IDR tree here
  // and populate ctx->programs array

  return VMI_SUCCESS;
}

/**
 * Enumerate eBPF maps from kernel structures  
 */
static int enumerate_ebpf_maps(vmi_instance_t vmi) {
  addr_t map_idr_addr;

  log_debug("Enumerating eBPF maps from kernel structures");

  if (vmi_translate_ksym2v(vmi, "map_idr", &map_idr_addr) != VMI_SUCCESS) {
    log_warn("Cannot locate eBPF map tracking structures");
    return VMI_FAILURE;
  }

  // TODO: Implement actual IDR walking for maps

  return VMI_SUCCESS;
}

/**
 * Check for suspicious kprobe attachments
 */
static int check_kprobe_hooks(ebpf_prog_info_t* prog) {
  // Check if program type is BPF_PROG_TYPE_KPROBE
  if (prog->type != 2) {  // BPF_PROG_TYPE_KPROBE = 2
    return 0;
  }

  // Check attachment point name for suspicious syscalls
  for (int i = 0; suspicious_syscalls[i]; i++) {
    if (strstr(prog->name, suspicious_syscalls[i])) {
      log_warn("Suspicious kprobe on syscall: %s", prog->name);
      return 1;
    }
  }

  return 0;
}

/**
 * Check for XDP programs that might be backdoors
 */
static int check_xdp_backdoor(ebpf_prog_info_t* prog) {
  // XDP programs (type 6) on main interfaces are suspicious
  if (prog->type != 6) {  // BPF_PROG_TYPE_XDP = 6
    return 0;
  }

  log_info("Found XDP program: %s (potential backdoor vector)", prog->name);

  // Check associated maps for C2 patterns
  for (uint32_t i = 0; i < prog->map_count && i < 16; i++) {
    log_debug("XDP program uses map ID: %u", prog->map_ids[i]);
  }

  return 1;  // XDP programs warrant investigation in most environments
}

/**
 * Check for hidden eBPF programs by comparing different data sources
 */
// NOLINTNEXTLINE
static int check_hidden_programs(vmi_instance_t vmi,
                                 ebpf_detection_ctx_t* ctx) {
  log_debug("Checking for hidden eBPF programs");

  // In a real implementation, we would:
  // 1. Count programs visible via bpf() syscall interface
  // 2. Count programs in kernel data structures
  // 3. Look for discrepancies

  // For now, we just check if we found any programs at all
  if (ctx->prog_count == 0) {
    log_debug("No eBPF programs found in kernel structures");
  }

  return 0;
}

/**
 * Analyze BPF maps for suspicious patterns
 */
static void analyze_bpf_maps(ebpf_detection_ctx_t* ctx) {
  log_debug("Analyzing %u BPF maps for suspicious patterns", ctx->map_count);

  for (uint32_t i = 0; i < ctx->map_count; i++) {
    ebpf_map_info_t* map = &ctx->maps[i];

    // Check for suspiciously large maps (data exfiltration)
    if (map->max_entries > 100000) {
      log_warn("Large BPF map detected: %s (%u entries)", map->name,
               map->max_entries);
      ctx->suspicious_flags |= EBPF_SUSPICIOUS_MAP_OVERFLOW;
    }

    // Check for maps with obfuscated names
    if (check_obfuscated_name(map->name)) {
      log_warn("BPF map with obfuscated name: %s", map->name);
      ctx->suspicious_flags |= EBPF_SUSPICIOUS_OBFUSCATED_NAME;
    }
  }
}

/**
 * Check system call table for BPF trampolines
 */
static int check_syscall_table_integrity(vmi_instance_t vmi) {
  addr_t sys_call_table_addr;

  log_debug("Checking syscall table integrity");

  if (vmi_translate_ksym2v(vmi, "sys_call_table", &sys_call_table_addr) !=
      VMI_SUCCESS) {
    log_debug("Cannot locate sys_call_table for integrity check");
    return VMI_FAILURE;
  }

  // TODO: Read syscall table entries and check for BPF trampolines
  // BPF trampolines have specific signatures we can look for

  return VMI_SUCCESS;
}

/**
 * Compare current state with previous state
 */
static void compare_with_previous_state(ebpf_detection_ctx_t* current) {
  if (first_run) {
    log_info("First eBPF state sampling run - establishing baseline");
    first_run = 0;
    return;
  }

  // Check for new programs
  if (current->prog_count > previous_ctx.prog_count) {
    log_warn("New eBPF programs detected: %u -> %u", previous_ctx.prog_count,
             current->prog_count);
    current->suspicious_flags |= EBPF_SUSPICIOUS_HIDDEN_PROG;
  }

  // Check for new maps
  if (current->map_count > previous_ctx.map_count) {
    log_warn("New eBPF maps detected: %u -> %u", previous_ctx.map_count,
             current->map_count);
  }

  // Check if suspicious flags increased
  if (current->suspicious_flags > previous_ctx.suspicious_flags) {
    log_warn("Suspicious activity level increased: 0x%x -> 0x%x",
             previous_ctx.suspicious_flags, current->suspicious_flags);
  }
}

/**
 * Generate detection report
 */
static void generate_detection_report(ebpf_detection_ctx_t* ctx) {
  log_info("=== eBPF State Detection Report ===");
  log_info("Programs found: %u", ctx->prog_count);
  log_info("Maps found: %u", ctx->map_count);
  log_info("Suspicious flags: 0x%04x", ctx->suspicious_flags);

  if (ctx->suspicious_flags == 0) {
    log_info("No suspicious eBPF activity detected");
    return;
  }

  log_warn("Suspicious eBPF activity detected:");

  if (ctx->suspicious_flags & EBPF_SUSPICIOUS_HIDDEN_PROG)
    log_warn("  - Hidden or new eBPF programs");
  if (ctx->suspicious_flags & EBPF_SUSPICIOUS_KPROBE_SYSCALL)
    log_warn("  - Suspicious syscall kprobes");
  if (ctx->suspicious_flags & EBPF_SUSPICIOUS_XDP_BACKDOOR)
    log_warn("  - Potential XDP backdoor");
  if (ctx->suspicious_flags & EBPF_SUSPICIOUS_TC_HIJACK)
    log_warn("  - TC filter hijacking");
  if (ctx->suspicious_flags & EBPF_SUSPICIOUS_TRACEPOINT_HOOK)
    log_warn("  - Suspicious tracepoint hooks");
  if (ctx->suspicious_flags & EBPF_SUSPICIOUS_MAP_OVERFLOW)
    log_warn("  - Abnormally large BPF maps");
  if (ctx->suspicious_flags & EBPF_SUSPICIOUS_OBFUSCATED_NAME)
    log_warn("  - Obfuscated program/map names");
  if (ctx->suspicious_flags & EBPF_SUSPICIOUS_GETDENTS_HOOK)
    log_warn("  - getdents hook (file hiding)");
}

/**
 * Save current state for next comparison
 */
static void save_current_state(ebpf_detection_ctx_t* current) {
  // Clean up previous state
  cleanup_detection_context(&previous_ctx);

  // Copy current state to previous
  previous_ctx.prog_count = current->prog_count;
  previous_ctx.map_count = current->map_count;
  previous_ctx.suspicious_flags = current->suspicious_flags;

  // Allocate and copy arrays if needed
  if (current->prog_count > 0) {
    previous_ctx.programs =
        calloc(current->prog_count, sizeof(ebpf_prog_info_t));
    if (previous_ctx.programs) {
      memcpy(previous_ctx.programs, current->programs,
             current->prog_count * sizeof(ebpf_prog_info_t));
    }
  }

  if (current->map_count > 0) {
    previous_ctx.maps = calloc(current->map_count, sizeof(ebpf_map_info_t));
    if (previous_ctx.maps) {
      memcpy(previous_ctx.maps, current->maps,
             current->map_count * sizeof(ebpf_map_info_t));
    }
  }
}

/**
 * Main state callback for eBPF artifact detection
 * Runs periodically to sample and analyze eBPF subsystem state
 */
uint32_t state_ebpf_artifacts_callback(vmi_instance_t vmi, void* context) {
  (void)context;  // Unused parameter

  ebpf_detection_ctx_t current_ctx;
  uint32_t result = VMI_SUCCESS;

  log_info("Starting eBPF state sampling");

  // Initialize detection context
  init_detection_context(&current_ctx);

  // Enumerate all eBPF programs
  if (enumerate_ebpf_programs(vmi, &current_ctx) != VMI_SUCCESS) {
    log_error("Failed to enumerate eBPF programs");
    result = VMI_FAILURE;
  }

  // Enumerate all eBPF maps
  if (enumerate_ebpf_maps(vmi) != VMI_SUCCESS) {
    log_error("Failed to enumerate eBPF maps");
    // Don't fail completely, continue with what we have
  }

  // Analyze each program for suspicious patterns
  for (uint32_t i = 0; i < current_ctx.prog_count; i++) {
    ebpf_prog_info_t* prog = &current_ctx.programs[i];

    // Check for known rootkit signatures
    if (check_known_rootkit_signature(prog->name)) {
      current_ctx.suspicious_flags |= EBPF_SUSPICIOUS_HIDDEN_PROG;
    }

    // Check for obfuscated names
    if (check_obfuscated_name(prog->name)) {
      current_ctx.suspicious_flags |= EBPF_SUSPICIOUS_OBFUSCATED_NAME;
    }

    // Check for suspicious kprobe hooks
    if (check_kprobe_hooks(prog)) {
      current_ctx.suspicious_flags |= EBPF_SUSPICIOUS_KPROBE_SYSCALL;
    }

    // Check for XDP backdoors
    if (check_xdp_backdoor(prog)) {
      current_ctx.suspicious_flags |= EBPF_SUSPICIOUS_XDP_BACKDOOR;
    }
  }

  // Check for hidden programs.
  if (check_hidden_programs(vmi, &current_ctx)) {
    current_ctx.suspicious_flags |= EBPF_SUSPICIOUS_HIDDEN_PROG;
  }

  // Analyze BPF maps.
  analyze_bpf_maps(&current_ctx);

  // Check syscall table integrity.
  check_syscall_table_integrity(vmi);

  // Compare with previous state.
  compare_with_previous_state(&current_ctx);

  // Generate detection report.
  generate_detection_report(&current_ctx);

  // Save current state for next comparison.
  save_current_state(&current_ctx);

  // Set result based on detection
  if (current_ctx.suspicious_flags != 0) {
    log_info("eBPF rootkit activity detected! Flags: 0x%04x",
             current_ctx.suspicious_flags);
    result = VMI_FAILURE;  // Indicate detection of suspicious activity
  }

  // Clean up current context
  cleanup_detection_context(&current_ctx);

  log_info("eBPF state sampling completed");
  return result;
}