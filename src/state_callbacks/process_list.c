#include "state_callbacks/process_list.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <string.h>

/**
 * @brief Structure to hold process information.
 */
typedef struct {
  vmi_pid_t pid;
  char* name;
  addr_t task_struct_addr;
  uint32_t uid, gid, euid, egid;
  uint32_t state;
  bool is_kernel_thread;
  addr_t mm_addr;  ///<  Memory management struct
} process_info_t;

/**
 * @brief Check if a task_struct represents a kernel thread.
 *
 * Kernel threads have their mm field set to NULL.
 *
 * @param vmi VMI instance
 * @param task_struct Address of the task_struct
 * @param mm_offset Offset of the mm field in the task_struct
 * @return true if it is a kernel thread, false otherwise
 */
static bool is_kernel_thread(vmi_instance_t vmi, addr_t task_struct,
                             unsigned long mm_offset) {
  addr_t mm_addr = 0;

  // Kernel threads have mm == NULL
  if (vmi_read_addr_va(vmi, task_struct + mm_offset, 0, &mm_addr) !=
      VMI_SUCCESS) {
    log_warn("Failed to read mm field at 0x%" PRIx64, task_struct);
    return false;
  }

  return (mm_addr == 0);
}

static bool read_process_credentials(vmi_instance_t vmi, addr_t task_struct,
                                     unsigned long cred_offset,
                                     process_info_t* proc_info) {
  addr_t cred_addr = 0;
  unsigned long uid_offset = 0, gid_offset = 0, euid_offset = 0,
                egid_offset = 0;

  // Get credential structure offsets
  if (vmi_get_offset(vmi, "linux_cred_uid", &uid_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_cred_gid", &gid_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_cred_euid", &euid_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_cred_egid", &egid_offset) != VMI_SUCCESS) {
    log_warn("Failed to get credential offsets");
    return false;
  }

  // Read credential structure pointer
  if (vmi_read_addr_va(vmi, task_struct + cred_offset, 0, &cred_addr) !=
      VMI_SUCCESS) {
    log_warn("Failed to read credentials pointer");
    return false;
  }

  if (cred_addr == 0) {
    log_warn("NULL credentials pointer");
    return false;
  }

  // Read credential values
  if (vmi_read_32_va(vmi, cred_addr + uid_offset, 0, &proc_info->uid) !=
          VMI_SUCCESS ||
      vmi_read_32_va(vmi, cred_addr + gid_offset, 0, &proc_info->gid) !=
          VMI_SUCCESS ||
      vmi_read_32_va(vmi, cred_addr + euid_offset, 0, &proc_info->euid) !=
          VMI_SUCCESS ||
      vmi_read_32_va(vmi, cred_addr + egid_offset, 0, &proc_info->egid) !=
          VMI_SUCCESS) {
    log_warn("Failed to read credential values");
    return false;
  }

  return true;
}

/**
 * @brief Print process information.
 *
 * @param proc_info Pointer to the process_info_t structure containing process details.
 */
static void print_process_info(const process_info_t* proc_info) {
  const char* thread_type = proc_info->is_kernel_thread ? "KERNEL" : "USER";
  const char* state_str;

  // Decode process state (simplified)
  switch (proc_info->state) {
    case 0:
      state_str = "RUNNING";
      break;
    case 1:
      state_str = "INTERRUPTIBLE";
      break;
    case 2:
      state_str = "UNINTERRUPTIBLE";
      break;
    case 4:
      state_str = "STOPPED";
      break;
    case 8:
      state_str = "TRACED";
      break;
    case 16:
      state_str = "ZOMBIE";
      break;
    case 32:
      state_str = "DEAD";
      break;
    default:
      state_str = "UNKNOWN";
      break;
  }

  log_info("PID %u: %s [%s] [%s] (task_struct=0x%" PRIx64 ")", proc_info->pid,
           proc_info->name, thread_type, state_str,
           proc_info->task_struct_addr);

  if (!proc_info->is_kernel_thread) {
    log_info("  Credentials: uid=%u gid=%u euid=%u egid=%u", proc_info->uid,
             proc_info->gid, proc_info->euid, proc_info->egid);
  }
}

// NOLINTNEXTLINE
uint32_t state_process_list_callback(vmi_instance_t vmi, void* context) {
  (void)context;

  addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
  addr_t current_process = 0;
  process_info_t proc_info = {0};

  // Required offsets
  unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0;
  unsigned long cred_offset = 0, state_offset = 0, mm_offset = 0;

  uint32_t total_processes = 0, kernel_threads = 0, user_processes = 0;

  // Get all required offsets
  if (vmi_get_offset(vmi, "linux_tasks", &tasks_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_name", &name_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_pid", &pid_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_cred", &cred_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_state", &state_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_mm", &mm_offset) != VMI_SUCCESS) {
    log_error("Failed to retrieve required offsets");
    return VMI_FAILURE;
  }

  // Get init_task address
  if (vmi_translate_ksym2v(vmi, "init_task", &list_head) != VMI_SUCCESS) {
    log_error("Failed to resolve init_task");
    return VMI_FAILURE;
  }

  list_head += tasks_offset;

  // Read first task pointer
  if (vmi_read_addr_va(vmi, list_head, 0, &next_list_entry) != VMI_SUCCESS) {
    log_error("Failed to read first task pointer");
    return VMI_FAILURE;
  }

  log_info("Starting kernel task list walk...");
  cur_list_entry = list_head;

  do {
    // Initialize for this iteration
    memset(&proc_info, 0, sizeof(proc_info));
    current_process = cur_list_entry - tasks_offset;
    proc_info.task_struct_addr = current_process;
    bool process_valid = true;

    // Read PID
    if (vmi_read_32_va(vmi, current_process + pid_offset, 0,
                       (uint32_t*)&proc_info.pid) != VMI_SUCCESS) {
      log_warn("Failed to read PID at 0x%" PRIx64, current_process);
      process_valid = false;
    }

    // Read process name
    if (process_valid) {
      proc_info.name = vmi_read_str_va(vmi, current_process + name_offset, 0);
      if (!proc_info.name) {
        log_warn("Failed to read process name for PID %u", proc_info.pid);
        process_valid = false;
      }
    }

    // Read process state
    if (process_valid) {
      if (vmi_read_32_va(vmi, current_process + state_offset, 0,
                         &proc_info.state) != VMI_SUCCESS) {
        log_warn("Failed to read process state for PID %u", proc_info.pid);
        proc_info.state = 0xFFFFFFFF;  // Unknown state
      }

      // Determine if kernel thread
      proc_info.is_kernel_thread =
          is_kernel_thread(vmi, current_process, mm_offset);

      // Read credentials for user processes
      if (!proc_info.is_kernel_thread) {
        if (!read_process_credentials(vmi, current_process, cred_offset,
                                      &proc_info)) {
          log_warn("Failed to read credentials for PID %u", proc_info.pid);
          // Continue anyway, just mark credentials as invalid
          proc_info.uid = proc_info.gid = proc_info.euid = proc_info.egid =
              0xFFFFFFFF;
        }
        user_processes++;
      } else {
        kernel_threads++;
      }

      // Print process information
      print_process_info(&proc_info);
      total_processes++;
    }

    // Cleanup process name
    if (proc_info.name) {
      g_free(proc_info.name);
      proc_info.name = NULL;
    }

    // Read next task pointer
    if (vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry) !=
        VMI_SUCCESS) {
      log_error("Failed to read next task pointer at 0x%" PRIx64,
                cur_list_entry);
      return VMI_FAILURE;
    }

    cur_list_entry = next_list_entry;

  } while (cur_list_entry != list_head);

  log_info("Finished walking kernel task list");
  log_info("Summary: %u total processes (%u user, %u kernel threads)",
           total_processes, user_processes, kernel_threads);

  return VMI_SUCCESS;
}