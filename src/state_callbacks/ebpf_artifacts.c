#include "state_callbacks/ebpf_artifacts.h"
#include <ctype.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <math.h>
#include <string.h>
#include <time.h>

/**
 * @brief Struct to keep information about an eBPF program.
 */
struct ebpf_prog_info_t {
  uint32_t id;    //< Unique identifier for the program.
  uint32_t type;  ///< Type of the program (e.g., kprobe, xdp).
  char name[64];  ///< Name of the program (optional name).
  uint32_t
      jited;  ///< Whether the program is JIT-compiled (1) or interpreted (0).
  uint32_t map_ids
      [16];  ///< IDs of maps used by the program (up to 16 for simplicity).
  uint32_t map_count;  ///< Number of maps used by the program.
};

/**
 * @brief Struct to keep information about an eBPF map.
 * An ebpf map is a key-value store used by eBPF programs to store and share data.
 */
struct ebpf_map_info_t {
  uint32_t id;           //< Unique identifier for the map.
  uint32_t type;         ///< Type of the map (e.g., hash-table, array)
  char name[64];         ///< Name of the map (optional name).
  uint32_t key_size;     ///< Size of the keys in bytes.
  uint32_t value_size;   ///< Size of the values in bytes.
  uint32_t max_entries;  ///< Maximum number of elements the map can hold.
  uint32_t flags;        ///< Flags associated with the map (e.g., read-only).
};

/**
 * @brief The eBPF JIT-related toggles of interest.
 */
struct ebpf_toggle_info_t {
  int present_enable, present_harden, present_kallsyms;
  int val_enable, val_harden, val_kallsyms;
};

// Type declarations for ease of use.
typedef struct ebpf_prog_info_t ebpf_prog_info_t;
typedef struct ebpf_map_info_t ebpf_map_info_t;
typedef struct ebpf_toggle_info_t ebpf_toggle_info_t;

/**
 * @brief The eBPF detection context.
 * Holds arrays of programs and maps, their counts and capacities, and toggle info.
 */
struct ebpf_detection_ctx_t {
  ebpf_prog_info_t* programs;
  ebpf_map_info_t* maps;
  uint32_t prog_count, prog_capacity;
  uint32_t map_count, map_capacity;
  ebpf_toggle_info_t toggles;
};

// Type declaration for ease of use.
typedef struct ebpf_detection_ctx_t ebpf_detection_ctx_t;

// Strings below are used for log-only hints, based on public PoCs.
static const char* known_rootkit_names[] = {
    "ebpfkit",    "triplecross", "bpfdoor", "badbpf",      "boopkit",
    "exechijack", "pidhide",     "sudoadd", "textreplace", NULL};

// Syscall names that, if found in a KPROBE program name, may indicate
// syscall probing hooks.
static const char* observed_syscalls[] = {"sys_getdents",
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

// Program type constants
// See: https://man7.org/linux/man-pages/man2/bpf.2.html
// Probes come in 5 different flavors: kprobe, kretprobe, uprobe, uretprobe, usdt. kprobe and kretprobe.
// See: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_KPROBE/
#define BPF_PROG_TYPE_KPROBE 2
#define BPF_PROG_TYPE_TRACEPOINT 5
#define BPF_PROG_TYPE_XDP 6

// Some default capacities for the map and program arrays.
#define PROG_CAPACITY 256
#define MAP_CAPACITY 512

/**
 * @brief Initialize the eBPF detection context
 * @param ctx Pointer to ebpf context to initialize.
 */
static void ebpf_detection_ctx_t_initialize(ebpf_detection_ctx_t* ctx) {
  ctx->prog_capacity = 256;
  ctx->map_capacity = 512;
  ctx->programs = g_new0(ebpf_prog_info_t, ctx->prog_capacity);
  ctx->maps = g_new0(ebpf_map_info_t, ctx->map_capacity);
  ctx->prog_count = 0;
  ctx->map_count = 0;
  memset(&ctx->toggles, 0, sizeof(ctx->toggles));
}

/**
 * @brief Free allocations inside the eBPF detection context.
 * @param ctx Pointer to ebpf context to clean up.
 */
static void ebpf_detection_ctx_t_cleanup(ebpf_detection_ctx_t* ctx) {
  if (ctx->programs) {
    g_free(ctx->programs);
    ctx->programs = NULL;
  }
  if (ctx->maps) {
    g_free(ctx->maps);
    ctx->maps = NULL;
  }
}

/**
 * @brief Log if the program/map name resembles known public PoC rootkits.
 * @details Names from public repositories (e.g., TripleCross, ebpfkit).
 *
 * @note See repositories:
 * * https://github.com/h3xduck/TripleCross
 * * https://github.com/Gui774ume/ebpfkit
 */
static void check_known_rootkit_signature(const char* name) {
  if (!name) {
    log_debug("Unnamed program (skipping rootkit name check)");
    return;
  }
  for (int i = 0; known_rootkit_names[i]; i++) {
    if (strstr(name, known_rootkit_names[i])) {
      log_debug("Known rootkit-like name detected: %s", name);
      return;
    }
  }
}

/**
 * @brief Log if a KPROBE program name hints at syscall instrumentation. Includes both entry and return probes.
 * @param prog Pointer to the eBPF program info structure.
 */
static void check_ebpf_kprobe_hooks(const ebpf_prog_info_t* prog) {
  if (prog->type != BPF_PROG_TYPE_KPROBE) {
    log_debug("Not a KPROBE program: %s", prog->name);
    return;
  }
  for (int i = 0; observed_syscalls[i]; i++)
    if (strstr(prog->name, observed_syscalls[i])) {
      log_debug("Program suggests syscall kprobe: %s", prog->name);
      return;
    }
}

/**
 * @brief Log if the program is a TRACEPOINT program.
 * @details Tracepoints are legitimate but can be abused; this is a cue.
 * For example, if a piece of malware wants to hook a kernel syscall, it can do so by loading an eBPF program of type BPF_PROG_TYPE_TRACEPOINT 
 * if the kernel already offers a tracepoint to the desired syscall (see /sys/kernel/debug/tracing/events/syscalls).
 * If the desired syscall does not have a tracepoint, the program can load a BPF_PROG_TYPE_KPROBE instead.
 * @note See: https://www.trendmicro.com/vinfo/us/security/news/threat-landscape/how-bpf-enabled-malware-works-bracing-for-emerging-threats
 * @param prog Pointer to the eBPF program info structure.
 */
static void check_ebpf_tracepoint_hooks(const ebpf_prog_info_t* prog) {
  if (prog->type != BPF_PROG_TYPE_TRACEPOINT) {
    log_debug("Not a TRACEPOINT program: %s", prog->name);
    return;
  }
  log_debug("TRACEPOINT program detected: %s", prog->name);
}

/**
 * @brief Log if the program is XDP (high-impact in RX path).
 * @details XDP runs at driver level, suitable for packet manipulation and
 * should be reviewed in environments where XDP is uncommon.
 * @note See: https://docs.cilium.io/en/stable/reference-guides/bpf/architecture.html
 * @param prog Pointer to the eBPF program info structure.
 */
static void check_xdp_backdoor(const ebpf_prog_info_t* prog) {
  if (prog->type != BPF_PROG_TYPE_XDP)
    return;
  log_debug("XDP program present: %s", prog->name);
  for (uint32_t i = 0; i < prog->map_count && i < 16; i++) {
    log_debug("XDP uses map ID: %u", prog->map_ids[i]);
  }
}

/**
 * @brief Light analysis of BPF maps (size and name)
 * @details Maps overview: https://www.kernel.org/doc/html/v6.0/bpf/maps.html
 * @param ctx Pointer to the eBPF detection context.
 */
static void analyze_bpf_maps(const ebpf_detection_ctx_t* ctx) {
  for (uint32_t i = 0; i < ctx->map_count; i++) {
    const ebpf_map_info_t* map = &ctx->maps[i];
    log_debug("BPF map: %s (max_entries=%u)", map->name, map->max_entries);
  }
}

/**
 * @brief Read a kernel integer toggle by symbol name. Used for bpf_jit_enable, bpf_jit_harden, bpf_jit_kallsyms.
 */
static int read_kernel_toggle(vmi_instance_t vmi, const char* sym,
                              int* out_value) {
  addr_t addr = 0;
  if (vmi_translate_ksym2v(vmi, sym, &addr) != VMI_SUCCESS || !addr)
    return 0;

  uint32_t tmp = 0;
  if (vmi_read_32_va(vmi, addr, 0, &tmp) != VMI_SUCCESS) {
    log_warn("eBPF toggle: failed to read %s @0x%" PRIx64, sym, (uint64_t)addr);
    return 0;
  }
  *out_value = (int)(int32_t)tmp;
  log_info("eBPF toggle: %s = %d (addr=0x%" PRIx64 ")", sym, *out_value,
           > (uint64_t)addr);
  return 1;
}

/**
 * @brief Audit eBPF JIT-related sysctls for visibility/hardening posture.
 * @note
 *  * bpf_jit_enable: enable JIT
 *    https://www.kernel.org/doc/html/v5.9/admin-guide/sysctl/net.html#bpf-jit-enable
 *  * bpf_jit_harden: harden JIT (0/1/2 semantics)
 *    https://www.kernel.org/doc/Documentation/sysctl/net.txt
 *  * bpf_jit_kallsyms: export JITed symbols (visibility)
 *    https://www.kernel.org/doc/html/v6.1/admin-guide/sysctl/net.html#bpf-jit-kallsyms
 */
static void audit_ebpf_runtime_toggles(vmi_instance_t vmi,
                                       ebpf_detection_ctx_t* ctx) {
  ebpf_toggle_info_t* t = &ctx->toggles;

  t->present_enable = read_kernel_toggle(vmi, "bpf_jit_enable", &t->val_enable);
  t->present_harden = read_kernel_toggle(vmi, "bpf_jit_harden", &t->val_harden);
  t->present_kallsyms =
      read_kernel_toggle(vmi, "bpf_jit_kallsyms", &t->val_kallsyms);

  if (t->present_enable && t->val_enable != 0) {
    if (t->present_harden && t->val_harden == 0)
      log_warn(
          "JIT enabled but hardening disabled (review security "
          "posture).");
    else if (!t->present_harden)
      log_warn("eBPF: JIT enabled; hardening status unknown (symbol missing).");

    if (t->present_kallsyms && t->val_kallsyms == 0)
      log_warn(
          "eBPF: bpf_jit_kallsyms is off; JITed programs may be absent from "
          "/proc/kallsyms.");
    else if (!t->present_kallsyms)
      log_warn(
          "eBPF: JIT enabled; kallsyms exposure unknown (symbol missing).");
  } else if (t->present_enable && t->val_enable == 0) {
    log_info("eBPF: JIT disabled (interpreter only).");
  } else if (!t->present_enable) {
    log_warn("eBPF: JIT status unknown (bpf_jit_enable symbol missing).");
  }
}

/**
 * @brief Log a short aggregated summary of what the sampler observed.
 * @note: This is considered a top level call for this callback so !log_debug may be used.
 */
static void calculate_program_type_counts(const ebpf_detection_ctx_t* ctx) {
  log_info("STATE_EBPF_ARTIFACTS: Programs sampled: %u", ctx->prog_count);
  log_info("STATE_EBPF_ARTIFACTS: Maps sampled:     %u", ctx->map_count);

  uint32_t kprobe = 0, xdp = 0, tracep = 0;
  for (uint32_t i = 0; i < ctx->prog_count; i++) {
    switch (ctx->programs[i].type) {
      case BPF_PROG_TYPE_KPROBE:
        kprobe++;
        break;
      case BPF_PROG_TYPE_XDP:
        xdp++;
        break;
      case BPF_PROG_TYPE_TRACEPOINT:
        tracep++;
        break;
      default:
        log_debug("Other program type: %u", ctx->programs[i].type);
        break;
    }
  }
  if (kprobe) {
    log_info("STATE_EBPF_ARTIFACTS: KPROBE program count: %u", kprobe);
  }
  if (xdp) {

    log_info("STATE_EBPF_ARTIFACTS: XDP program count: %u", xdp);
  }
  if (tracep) {

    log_info("STATE_EBPF_ARTIFACTS: TRACEPOINT program count: %u", tracep);
  }
}

uint32_t state_ebpf_artifacts_callback(vmi_instance_t vmi, void* context) {
  (void)context;

  ebpf_detection_ctx_t ctx;
  uint32_t result = VMI_SUCCESS;

  log_info("Executing STATE_EBPF_ARTIFACTS callback.");

  ebpf_detection_ctx_t_initialize(&ctx);
  audit_ebpf_runtime_toggles(vmi, &ctx);

  for (uint32_t i = 0; i < ctx.prog_count; i++) {
    const ebpf_prog_info_t* program = &ctx.programs[i];
    check_known_rootkit_signature(program->name);
    check_ebpf_kprobe_hooks(program);
    check_ebpf_tracepoint_hooks(program);
    check_xdp_backdoor(program);
  }
  analyze_bpf_maps(&ctx);

  calculate_program_type_counts(&ctx);

  ebpf_detection_ctx_t_cleanup(&ctx);

  log_info("STATE_EBPF_ARTIFACTS callback completed.");

  return result;
}
