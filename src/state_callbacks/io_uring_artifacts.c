#include "state_callbacks/io_uring_artifacts.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "event_handler.h"
#include "offsets.h"
#include "state_callbacks/responses/io_uring_artifacts_response.h"
#include "utils.h"

#include <libvmi/libvmi.h>

/**
 * @brief Read a guest virtual address with a single retry on failure.
 * 
 * @note io_uring resources are torn down asynchronously; a single retry HELPS
 * avoid false negatives when a pointer is observed during teardown.
 * 
 * @param vmi The VMI instance.
 * @param virtual_addr The virtual address to read from.
 * @param out The value read from the virtual address.
 * @return status_t The status of the read operation.
 */
static inline status_t vmi_read_addr_va_retry(vmi_instance_t vmi,
                                              addr_t virtual_addr,
                                              addr_t* out) {
  if (vmi_read_addr_va(vmi, virtual_addr, 0, out) == VMI_SUCCESS)
    return VMI_SUCCESS;
  return vmi_read_addr_va(vmi, virtual_addr, 0, out);
}

/**
 * @brief Read a 32 bit value from a guest virtual address with a single retry on failure.
 * 
 * @param vmi The VMI instance.
 * @param virtual_addr The virtual address to read from.
 * @param out The value read from the virtual address.
 * @return status_t The status of the read operation.
 */
static inline status_t vmi_read_u32_va_retry(vmi_instance_t vmi,
                                             addr_t virtual_addr,
                                             uint32_t* out) {
  if (vmi_read_32_va(vmi, virtual_addr, 0, out) == VMI_SUCCESS)
    return VMI_SUCCESS;
  return vmi_read_32_va(vmi, virtual_addr, 0, out);
}

/**
 * @brief Check if the io_uring SQ/CQ geometry is sane.
 * 
 * @param sqe The number of SQ entries.
 * @param cqe The number of CQ entries.
 * @return true if the geometry is sane, false otherwise. 
 */
static inline bool geometry_sane(uint32_t sqe, uint32_t cqe) {
  if (sqe == 0 || cqe == 0)
    return false;
  /* CQ entries are >= SQ entries; man page: cq_entries must be > entries and may be rounded to next power-of-two.
   * man7: https://man7.org/linux/man-pages/man2/io_uring_setup.2.html  (IORING_SETUP_CQSIZE)
   */
  if (cqe < sqe)
    return false;
  return true;
}

/**
 * @brief Check if a 32-bit unsigned integer is a power of two.
 * 
 * @param value The integer to check.
 * @return true if the integer is a power of two, false otherwise. 
 */
static inline bool is_power_of_two_u32(uint32_t value) {
  return value && ((value & (value - 1)) == 0);
}

/**

 * @brief  Inspect io_uring state of a single task_struct.
 *
 * @details
 * Pointer chain (upstream kernels):
 *   task_struct -> io_uring (struct io_uring_task *) -> last (struct io_ring_ctx *)
 *   -> rings (struct io_rings *)
 * References:
 *  * Types/fields: io_uring_types.h (io_uring_task, io_ring_ctx, io_rings)
 *       https://chromium.googlesource.com/chromiumos/third_party/kernel-next/+/refs/heads/main/include/linux/io_uring_types.h
 *  * Context/rings linkage in fs/io_uring.c:
 *       https://lxr.missinglinkelectronics.com/linux/fs/io_uring.c
 *  * Background on SQ/CQ rings:
 *       https://man7.org/linux/man-pages/man7/io_uring.7.html
 * 
 * @param vmi The VMI instance.
 * @param task_struct_addr The address of the task_struct to inspect.
 * @param pid The process ID of the task_struct.
 * @param procname The process name of the task_struct.
 * @param data The io_uring artifacts state data to populate.
 */
static void inspect_io_uring_for_task(vmi_instance_t vmi,
                                      // NOLINTNEXTLINE
                                      addr_t task_struct_addr, vmi_pid_t pid,
                                      const char* procname,
                                      io_uring_artifacts_state_data_t* data) {
  addr_t io_uring_task = 0;
  if (vmi_read_addr_va_retry(vmi, task_struct_addr + LINUX_OFFSET_TASK_IO_URING,
                             &io_uring_task) != VMI_SUCCESS ||
      !io_uring_task) {
    log_debug("PID %u (%s): no io_uring (NULL)", pid,
              procname ? procname : "?");
    return;
  }

  log_debug("PID %u (%s): found io_uring_task=0x%" PRIx64, pid,
            procname ? procname : "?", (uint64_t)io_uring_task);

  addr_t ctx = 0;
  if (vmi_read_addr_va_retry(vmi,
                             io_uring_task + LINUX_OFFSET_IO_URING_TASK_LAST,
                             &ctx) != VMI_SUCCESS ||
      !ctx) {
    log_debug("PID %u (%s): io_uring_task=0x%" PRIx64 " but 'last' ctx is NULL",
              pid, procname ? procname : "?", (uint64_t)io_uring_task);
    return;
  }

  addr_t rings = 0;
  if (vmi_read_addr_va_retry(vmi, ctx + LINUX_OFFSET_IO_RING_CTX_RINGS,
                             &rings) != VMI_SUCCESS ||
      !rings) {
    log_debug("PID %u (%s): ctx=0x%" PRIx64 " has no rings (NULL)", pid,
              procname ? procname : "?", (uint64_t)ctx);
    return;
  }

  uint32_t sq_entries = 0, cq_entries = 0;
  if (vmi_read_u32_va_retry(vmi, rings + LINUX_OFFSET_IO_RINGS_SQ_ENTRIES,
                            &sq_entries) != VMI_SUCCESS ||
      vmi_read_u32_va_retry(vmi, rings + LINUX_OFFSET_IO_RINGS_CQ_ENTRIES,
                            &cq_entries) != VMI_SUCCESS) {
    log_debug("PID %u (%s): failed to read ring sizes from rings=0x%" PRIx64,
              pid, procname ? procname : "?", (uint64_t)rings);
    return;
  }

  // Log observed geometry so you can verify offsets against known-good runs.
  log_debug("PID %u (%s): io_uring ctx=0x%" PRIx64 " rings=0x%" PRIx64
            " SQ=%u CQ=%u",
            pid, procname ? procname : "?", (uint64_t)ctx, (uint64_t)rings,
            sq_entries, cq_entries);

  // Separate obviously suspicious geometry (race/offset issue) from normal.
  if (!geometry_sane(sq_entries, cq_entries)) {
    /* Strong signal (likely wrong offsets or torn-down rings):
     *  * man7 IORING_SETUP_CQSIZE: CQ must be > entries (SQ requested depth).
     *     https://man7.org/linux/man-pages/man2/io_uring_setup.2.html
     */
    log_debug(
        "PID %u (%s): INVALID ring geometry (SQ=%u, CQ=%u). "
        "Per ABI, CQ must be >= SQ (usually > SQ). Check offsets or teardown "
        "race.",
        pid, procname ? procname : "?", sq_entries, cq_entries);
  }

  // Both rings are sized to powers of two (rounded up by kernel).
  //   - man7 (rounded to next power of two): https://man7.org/linux/man-pages/man2/io_uring_setup.2.html
  bool sq_power_of_two = is_power_of_two_u32(sq_entries);
  bool cq_power_of_two = is_power_of_two_u32(cq_entries);

  if (!sq_power_of_two) {
    log_debug("PID %u (%s): SQ entries (%u) not power-of-two.", pid,
              procname ? procname : "?", sq_entries);
  }
  if (!cq_power_of_two) {
    log_debug(
        "PID %u (%s): CQ entries (%u) not power-of-two; possibly created with "
        "CQSIZE (still rounded by kernel).",
        pid, procname ? procname : "?", cq_entries);
  }

  // Check if instance is suspicious
  bool is_suspicious = false;
  if (!geometry_sane(sq_entries, cq_entries)) {
    is_suspicious = true;
  }
  // Additional suspicious patterns could be added here

  // Add instance to data structure
  if (data) {
    io_uring_artifacts_state_add_instance(
        data, pid, procname, (uint64_t)io_uring_task, (uint64_t)ctx,
        (uint64_t)rings, sq_entries, cq_entries,
        geometry_sane(sq_entries, cq_entries), sq_power_of_two, cq_power_of_two,
        is_suspicious);
  }
}

uint32_t state_io_uring_artifacts_callback(vmi_instance_t vmi, void* context) {
  // Preconditions
  if (!vmi || !context) {
    return log_error_and_queue_response_task(
        "io_uring_artifacts_state", STATE_IO_URING_ARTIFACTS, INVALID_ARGUMENTS,
        "STATE_IO_URING_ARTIFACTS: Invalid arguments to io_uring artifacts "
        "state callback");
  }

  event_handler_t* event_handler = (event_handler_t*)context;
  if (!event_handler || !event_handler->is_paused) {
    return log_error_and_queue_response_task(
        "io_uring_artifacts_state", STATE_IO_URING_ARTIFACTS, INVALID_ARGUMENTS,
        "STATE_IO_URING_ARTIFACTS: Callback requires a valid event handler "
        "context");
  }

  log_info("Executing STATE_IO_URING_ARTIFACTS callback.");

  // Create io_uring artifacts state data structure
  io_uring_artifacts_state_data_t* artifacts_data =
      io_uring_artifacts_state_data_new();
  if (!artifacts_data) {
    return log_error_and_queue_response_task(
        "io_uring_artifacts_state", STATE_IO_URING_ARTIFACTS,
        MEMORY_ALLOCATION_FAILURE,
        "STATE_IO_URING_ARTIFACTS: Failed to allocate memory for io_uring "
        "artifacts state data");
  }

  addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
  addr_t current_task = 0;
  char* procname = NULL;
  vmi_pid_t pid = 0;
  unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0;

  /* Weak corroboration only; do not classify based on these counters.
   * Thread naming references:
   *  * SQPOLL worker naming (iou-sqp*): https://man7.org/linux/man-pages/man2/io_uring_setup.2.html (IORING_SETUP_SQPOLL)
   *  * Worker pool: https://blog.cloudflare.com/missing-manuals-io_uring-worker-pool/
   */

  // Using IORING_SETUP_SQPOLL will, by default, create two threads in your process, one named iou-sqp-TID, and the other named iou-wrk-TID.
  uint64_t iou_worker_count = 0;  // threads named "iou-wrk*"
  uint64_t iou_sqp_count = 0;     // threads named "iou-sqp*"


  if (vmi_get_offset(vmi, "linux_tasks", &tasks_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_pid", &pid_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_name", &name_offset) != VMI_SUCCESS) {
    io_uring_artifacts_state_data_free(artifacts_data);
    return log_error_and_queue_response_task(
        "io_uring_artifacts_state", STATE_IO_URING_ARTIFACTS, VMI_OP_FAILURE,
        "STATE_IO_URING_ARTIFACTS: Failed to retrieve required task_struct "
        "offsets from profile");
  }

  if (vmi_translate_ksym2v(vmi, "init_task", &list_head) != VMI_SUCCESS) {
    io_uring_artifacts_state_data_free(artifacts_data);
    return log_error_and_queue_response_task(
        "io_uring_artifacts_state", STATE_IO_URING_ARTIFACTS, VMI_OP_FAILURE,
        "STATE_IO_URING_ARTIFACTS: Failed to resolve init_task");
  }

  list_head += tasks_offset;
  if (vmi_read_addr_va_retry(vmi, list_head, &next_list_entry) != VMI_SUCCESS) {
    io_uring_artifacts_state_data_free(artifacts_data);
    return log_error_and_queue_response_task(
        "io_uring_artifacts_state", STATE_IO_URING_ARTIFACTS, VMI_OP_FAILURE,
        "STATE_IO_URING_ARTIFACTS: Failed to read first task pointer");
  }

  cur_list_entry = list_head;

  /* Loop safety: cap the number of visited tasks to avoid hangs if the list is corrupt. */
  /* Safety cap: abort if >1,048,576 tasks visited.
   * Real systems rarely exceed ~10^5 (hihi) processes/threads; this upper bound
   * is far above practical counts but prevents infinite loops if the
   * task list is corrupted.
   */
  size_t visited = 0;
  const size_t visited_cap = 1 << 20;

  do {
    if (++visited > visited_cap) {
      io_uring_artifacts_state_data_free(artifacts_data);
      return log_error_and_queue_response_task(
          "io_uring_artifacts_state", STATE_IO_URING_ARTIFACTS, VMI_OP_FAILURE,
          "STATE_IO_URING_ARTIFACTS: Aborting; task list walk exceeded cap");
    }

    /* Read the next pointer up-front to make advancement unconditional and remove goto. */
    addr_t next_after = 0;
    if (vmi_read_addr_va_retry(vmi, cur_list_entry, &next_after) !=
        VMI_SUCCESS) {
      io_uring_artifacts_state_data_free(artifacts_data);
      return log_error_and_queue_response_task(
          "io_uring_artifacts_state", STATE_IO_URING_ARTIFACTS, VMI_OP_FAILURE,
          "STATE_IO_URING_ARTIFACTS: Failed to read next task pointer");
    }

    current_task = cur_list_entry - tasks_offset;

    if (vmi_read_32_va(vmi, current_task + pid_offset, 0, (uint32_t*)&pid) !=
        VMI_SUCCESS) {
      log_debug("STATE_IO_URING_ARTIFACTS: Failed to read PID at 0x%" PRIx64
                ". Skipping task...",
                (uint64_t)current_task);
      cur_list_entry = next_after;
      continue;
    }

    procname = vmi_read_str_va(vmi, current_task + name_offset, 0);

    // These names often belong to io_uring worker/sqpoll threads. Weak signal only.
    if (procname) {
      if (g_str_has_prefix(procname, "iou-wrk"))
        iou_worker_count++;
      else if (g_str_has_prefix(procname, "iou-sqp"))
        iou_sqp_count++;
    }

    inspect_io_uring_for_task(vmi, current_task, pid, procname, artifacts_data);

    if (procname) {
      g_free(procname);
      procname = NULL;
    }

    /* Advance using the already-read pointer. */
    cur_list_entry = next_after;

  } while (cur_list_entry != list_head);

  // Set worker thread information
  io_uring_artifacts_state_set_worker_threads(artifacts_data, iou_worker_count,
                                              iou_sqp_count);

  // Set summary information
  uint32_t total_instances = artifacts_data->io_uring_instances->len;
  uint32_t suspicious_instances = 0;
  for (guint i = 0; i < artifacts_data->io_uring_instances->len; i++) {
    io_uring_instance_info_t* instance = &g_array_index(
        artifacts_data->io_uring_instances, io_uring_instance_info_t, i);
    if (instance->is_suspicious) {
      suspicious_instances++;
    }
  }

  io_uring_artifacts_state_set_summary(
      artifacts_data, total_instances, suspicious_instances,
      iou_worker_count + iou_sqp_count, visited);

  /* Expected geometry:
   * CQ often >= SQ, historically sometimes 2x; apps may request larger CQ via CQSIZE.
   * See: 
   *  * https://man7.org/linux/man-pages/man2/io_uring_setup.2.html
   *  * https://lxr.missinglinkelectronics.com/linux/fs/io_uring.c
   */
  log_warn(
      "STATE_IO_URING_ARTIFACTS: Finished scanning io_uring artifacts across "
      "all tasks. Weak signals: iou-wrk=%" PRIu64 ", iou-sqp=%" PRIu64,
      iou_worker_count, iou_sqp_count);

  if (suspicious_instances > 0) {
    log_warn(
        "STATE_IO_URING_ARTIFACTS: Found %u suspicious io_uring instances.",
        suspicious_instances);
  } else {
    log_info(
        "STATE_IO_URING_ARTIFACTS: No suspicious io_uring instances detected");
  }

  log_info("STATE_IO_URING_ARTIFACTS callback completed.");

  return log_success_and_queue_response_task(
      "io_uring_artifacts_state", STATE_IO_URING_ARTIFACTS, artifacts_data,
      (void (*)(void*))io_uring_artifacts_state_data_free);
}
