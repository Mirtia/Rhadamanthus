#include "state_callbacks/process_list.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>

uint32_t state_process_list_callback(vmi_instance_t vmi, void* context) {
  (void)context;

  addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
  addr_t current_process = 0;
  char* procname = NULL;
  vmi_pid_t pid = 0;
  unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0;

  if (vmi_get_offset(vmi, "linux_tasks", &tasks_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_name", &name_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_pid", &pid_offset) != VMI_SUCCESS) {
    log_error("Failed to retrieve required offsets.");
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
    current_process = cur_list_entry - tasks_offset;

    if (vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid) !=
        VMI_SUCCESS) {
      log_warn("Failed to read PID at 0x%" PRIx64, current_process);
      break;
    }

    procname = vmi_read_str_va(vmi, current_process + name_offset, 0);
    if (!procname) {
      log_warn("Failed to read process name for PID %u", pid);
      break;
    }

    log_info("PID %u: %s (task_struct=0x%" PRIx64 ")", pid,
             procname, current_process);

    g_free(procname);
    procname = NULL;

    if (vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry) !=
        VMI_SUCCESS) {
      log_error("Failed to read next task pointer at 0x%" PRIx64,
                cur_list_entry);
      return VMI_FAILURE;
    }

    cur_list_entry = next_list_entry;

  } while (cur_list_entry != list_head);

  log_info("Finished walking kernel task list.");

  return VMI_SUCCESS;
}
