#include "state_callbacks/io_uring_artifacts.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libvmi/libvmi.h>

/*
 * Hardcoded offsets for io_uring-related structures.
 * These values were derived from kernel vmlinux-5.15.0-139-generic.
 * TODO: Add to libvmi profile along with all the offset things :(.
 */
static const unsigned long offset_task_io_uring = 0x1280;
static const unsigned long offset_io_uring_task_last = 0x20;
static const unsigned long offset_io_ring_ctx_rings = 0xd0;
static const unsigned long offset_io_rings_sq_entries = 0x10;
static const unsigned long offset_io_rings_cq_entries = 0x14;

/* REASON: io_uring resources are torn down asynchronously; a single retry HELPS
 * avoid false negatives when a pointer is observed during teardown. */
static inline status_t vmi_read_addr_va_retry(vmi_instance_t vmi,
                                              addr_t virtual_addr,
                                              addr_t* out) {
  if (vmi_read_addr_va(vmi, virtual_addr, 0, out) == VMI_SUCCESS)
    return VMI_SUCCESS;
  return vmi_read_addr_va(vmi, virtual_addr, 0, out);
}

static inline status_t vmi_read_u32_va_retry(vmi_instance_t vmi,
                                             addr_t virtual_addr,
                                             uint32_t* out) {
  if (vmi_read_32_va(vmi, virtual_addr, 0, out) == VMI_SUCCESS)
    return VMI_SUCCESS;
  return vmi_read_32_va(vmi, virtual_addr, 0, out);
}

static inline bool geometry_sane(uint32_t sqe, uint32_t cqe) {
  if (sqe == 0 || cqe == 0)
    return false;
  /* Heuristic: CQ is commonly >= SQ. Not a hard rule, but useful as a filter. */
  if (cqe < sqe)
    return false;
  return true;
}

static inline bool is_power_of_two_u32(uint32_t value) {
  return value && ((value & (value - 1)) == 0);
}

/**
 * @brief Inspect io_uring state of a single task_struct.
 *
 * (task->io_uring -> io_uring_task->last),
 * with race-tolerant reads and geometry checks so results are more reliable.
 */
static void inspect_io_uring_for_task(vmi_instance_t vmi,
                                      // NOLINTNEXTLINE
                                      addr_t task_struct_addr, vmi_pid_t pid,
                                      const char* procname) {
  addr_t io_uring_task = 0;
  if (vmi_read_addr_va_retry(vmi, task_struct_addr + offset_task_io_uring,
                             &io_uring_task) != VMI_SUCCESS ||
      !io_uring_task) {
    // log_debug("PID %u (%s): no io_uring (NULL)", pid, procname ? procname : "?");
    return;
  }

  addr_t ctx = 0;
  if (vmi_read_addr_va_retry(vmi, io_uring_task + offset_io_uring_task_last,
                             &ctx) != VMI_SUCCESS ||
      !ctx) {
    log_info("PID %u (%s): io_uring_task=0x%" PRIx64 " but 'last' ctx is NULL",
             pid, procname ? procname : "?", (uint64_t)io_uring_task);
    return;
  }

  addr_t rings = 0;
  if (vmi_read_addr_va_retry(vmi, ctx + offset_io_ring_ctx_rings, &rings) !=
          VMI_SUCCESS ||
      !rings) {
    log_debug("PID %u (%s): ctx=0x%" PRIx64 " has no rings (NULL)", pid,
              procname ? procname : "?", (uint64_t)ctx);
    return;
  }

  uint32_t sq_entries = 0, cq_entries = 0;
  if (vmi_read_u32_va_retry(vmi, rings + offset_io_rings_sq_entries,
                            &sq_entries) != VMI_SUCCESS ||
      vmi_read_u32_va_retry(vmi, rings + offset_io_rings_cq_entries,
                            &cq_entries) != VMI_SUCCESS) {
    log_warn("PID %u (%s): failed to read ring sizes from rings=0x%" PRIx64,
             pid, procname ? procname : "?", (uint64_t)rings);
    return;
  }

  // Log observed geometry so you can verify offsets against known-good runs.
  log_info("PID %u (%s): io_uring ctx=0x%" PRIx64 " rings=0x%" PRIx64
           " SQ=%u CQ=%u",
           pid, procname ? procname : "?", (uint64_t)ctx, (uint64_t)rings,
           sq_entries, cq_entries);

  // Separate obviously suspicious geometry (race/offset issue) from normal.
  if (!geometry_sane(sq_entries, cq_entries)) {
    log_warn(
        "PID %u (%s): suspicious ring geometry (SQ=%u, CQ=%u). "
        "May be teardown race or wrong offsets.",
        pid, procname ? procname : "?", sq_entries, cq_entries);
  }

  // Allowed with IORING_SETUP_CQSIZE; warn to aid triage, not to flag.
  if (!is_power_of_two_u32(cq_entries)) {
    log_warn(
        "PID %u (%s): CQ entries (%u) not power-of-two; possibly created with "
        "CQSIZE.",
        pid, procname ? procname : "?", cq_entries);
  }
}

uint32_t state_io_uring_artifacts_callback(vmi_instance_t vmi, void* context) {
  (void)context;

  addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
  addr_t current_task = 0;
  char* procname = NULL;
  vmi_pid_t pid = 0;
  unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0;

  /* REASON: Weak corroboration only; do not classify based on these counters. */
  uint64_t iou_worker_count = 0; /* threads named "iou-wrk*" */
  uint64_t iou_sqp_count = 0;    /* threads named "iou-sqp*" */

  log_info("Executing STATE_IO_URING_ARTIFACTS callback.");

  if (vmi_get_offset(vmi, "linux_tasks", &tasks_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_pid", &pid_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_name", &name_offset) != VMI_SUCCESS) {
    log_error("Failed to retrieve required task_struct offsets from profile.");
    return VMI_FAILURE;
  }

  if (vmi_translate_ksym2v(vmi, "init_task", &list_head) != VMI_SUCCESS) {
    log_error("Failed to resolve init_task.");
    return VMI_FAILURE;
  }

  list_head += tasks_offset;
  if (vmi_read_addr_va_retry(vmi, list_head, &next_list_entry) != VMI_SUCCESS) {
    log_error("Failed to read first task pointer.");
    return VMI_FAILURE;
  }

  cur_list_entry = list_head;
  do {
    current_task = cur_list_entry - tasks_offset;

    if (vmi_read_32_va(vmi, current_task + pid_offset, 0, (uint32_t*)&pid) !=
        VMI_SUCCESS) {
      log_warn("Failed to read PID at 0x%" PRIx64, (uint64_t)current_task);
      break;
    }

    procname = vmi_read_str_va(vmi, current_task + name_offset, 0);

    /* These names often belong to io_uring worker/sqpoll threads. Weak signal only. */
    if (procname) {
      if (g_str_has_prefix(procname, "iou-wrk"))
        iou_worker_count++;
      else if (g_str_has_prefix(procname, "iou-sqp"))
        iou_sqp_count++;
    }

    inspect_io_uring_for_task(vmi, current_task, pid, procname);

    if (procname) {
      g_free(procname);
      procname = NULL;
    }

    if (vmi_read_addr_va_retry(vmi, cur_list_entry, &next_list_entry) !=
        VMI_SUCCESS) {
      log_error("Failed to read next task pointer at 0x%" PRIx64,
                (uint64_t)cur_list_entry);
      return VMI_FAILURE;
    }

    cur_list_entry = next_list_entry;

  } while (cur_list_entry != list_head);

  log_info(
      "Finished scanning io_uring artifacts across all tasks. "
      "Weak signals: iou-wrk=%" PRIu64 ", iou-sqp=%" PRIu64,
      iou_worker_count, iou_sqp_count);

  return VMI_SUCCESS;
}
