#include "state_callbacks/io_uring_artifacts.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * Hardcoded offsets for io_uring-related structures.
 * Replace these values with output from pahole --hex on vmlinux.
 * These values were derived from kernel vmlinux-5.15.0-139-generic.
 */
static const unsigned long offset_task_io_uring = 0x1280;
static const unsigned long offset_io_uring_task_last = 0x20;
static const unsigned long offset_io_ring_ctx_rings = 0xd0;
static const unsigned long offset_io_rings_sq_entries = 0x10;
static const unsigned long offset_io_rings_cq_entries = 0x14;

/**
 * @brief Inspect io_uring state of a single task_struct.
 */
static void inspect_io_uring_for_task(vmi_instance_t vmi,
                                      // NOLINTNEXTLINE
                                      addr_t task_struct_addr, vmi_pid_t pid,
                                      const char* procname) {
  addr_t io_uring_task = 0;
  if (vmi_read_addr_va(vmi, task_struct_addr + offset_task_io_uring, 0,
                       &io_uring_task) != VMI_SUCCESS ||
      !io_uring_task) {
    log_info(
        "PID %u (%s): No io_uring state found in task_struct at 0x%" PRIx64,
        pid, procname ? procname : "?", (uint64_t)task_struct_addr);
    return;  // task has no io_uring state
  }

  addr_t ctx = 0;
  if (vmi_read_addr_va(vmi, io_uring_task + offset_io_uring_task_last, 0,
                       &ctx) != VMI_SUCCESS ||
      !ctx) {
    log_info("PID %u (%s): No io_uring ctx found at 0x%" PRIx64, pid,
             procname ? procname : "?", (uint64_t)io_uring_task);
    return;
  }

  addr_t rings = 0;
  if (vmi_read_addr_va(vmi, ctx + offset_io_ring_ctx_rings, 0, &rings) !=
          VMI_SUCCESS ||
      !rings) {
    log_info("PID %u (%s): No io_uring rings found at 0x%" PRIx64
             " for ctx=0x%" PRIx64,
             pid, procname ? procname : "?", (uint64_t)io_uring_task,
             (uint64_t)ctx);
    return;
  }

  uint32_t sq_entries = 0, cq_entries = 0;
  (void)vmi_read_32_va(vmi, rings + offset_io_rings_sq_entries, 0, &sq_entries);
  (void)vmi_read_32_va(vmi, rings + offset_io_rings_cq_entries, 0, &cq_entries);

  log_info("PID %u (%s): io_uring ctx=0x%" PRIx64 " rings=0x%" PRIx64
           " SQ=%u CQ=%u",
           pid, procname ? procname : "?", (uint64_t)ctx, (uint64_t)rings,
           sq_entries, cq_entries);
}

uint32_t state_io_uring_artifacts_callback(vmi_instance_t vmi, void* context) {
  (void)context;

  addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
  addr_t current_task = 0;
  char* procname = NULL;
  vmi_pid_t pid = 0;
  unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0;

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
  if (vmi_read_addr_va(vmi, list_head, 0, &next_list_entry) != VMI_SUCCESS) {
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

    inspect_io_uring_for_task(vmi, current_task, pid, procname);

    if (procname) {
      g_free(procname);
      procname = NULL;
    }

    if (vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry) !=
        VMI_SUCCESS) {
      log_error("Failed to read next task pointer at 0x%" PRIx64,
                (uint64_t)cur_list_entry);
      return VMI_FAILURE;
    }

    cur_list_entry = next_list_entry;

  } while (cur_list_entry != list_head);

  log_info("Finished scanning io_uring artifacts across all tasks.");
  return VMI_SUCCESS;
}
