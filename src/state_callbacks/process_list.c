#include "state_callbacks/process_list.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <string.h>
#include "event_handler.h"
#include "offsets.h"

/**
 * @brief Structure to hold process information.
 */
typedef struct {
  vmi_pid_t pid;                  ///< Process ID.
  char* name;                     ///< Process name (comm).
  addr_t task_struct_addr;        ///< Address of the task_struct.
  uint32_t uid, gid, euid, egid;  ///< Credentials.
  uint32_t state;                 ///< Process state.
  bool is_kernel_thread;          ///< Flag indicating if it's a kernel thread.
  addr_t mm_addr;                 ///<  Memory management struct.
} process_info_t;

/**
 * @brief Check if a task_struct represents a kernel thread.
 *
 * @note Kernel threads have their mm field set to NULL."tsk->mm" points to the "real address space". 
 * For an anonymous process, tsk->mm will be NULL, for the logical reason that an anonymous process
 * really doesn't have a real address space at all.
 * https://docs.kernel.org/mm/active_mm.html
 *
 * @param vmi VMI instance.
 * @param task_struct Address of the task_struct.
 * @param mm_offset Offset of the mm field in the task_struct.
 * @return true if it is a kernel thread, false otherwise.
 */
static bool is_kernel_thread(vmi_instance_t vmi, addr_t task_struct,
                             unsigned long mm_offset) {
  addr_t mm_addr = 0;
  if (vmi_read_addr_va(vmi, task_struct + mm_offset, 0, &mm_addr) !=
      VMI_SUCCESS) {
    log_debug("Failed to read mm field at 0x%" PRIx64, task_struct);
    return false;
  }

  return (mm_addr == 0);
}

static bool read_process_credentials(vmi_instance_t vmi, addr_t task_struct,
                                     unsigned long cred_offset,
                                     process_info_t* proc_info) {
  addr_t cred_addr = 0;
  if (vmi_read_addr_va(vmi, task_struct + cred_offset, 0, &cred_addr) !=
      VMI_SUCCESS) {
    log_debug("Failed to read credentials pointer");
    return false;
  }

  if (cred_addr == 0) {
    log_debug("NULL credentials pointer");
    return false;
  }

  // Read credentials.
  // See: https://docs.kernel.org/security/credentials.html.
  if (vmi_read_32_va(vmi, cred_addr + LINUX_EUID_OFFSET, 0, &proc_info->uid) !=
          VMI_SUCCESS ||
      vmi_read_32_va(vmi, cred_addr + LINUX_GID_OFFSET, 0, &proc_info->gid) !=
          VMI_SUCCESS ||
      vmi_read_32_va(vmi, cred_addr + LINUX_EUID_OFFSET, 0, &proc_info->euid) !=
          VMI_SUCCESS ||
      vmi_read_32_va(vmi, cred_addr + LINUX_EGID_OFFSET, 0, &proc_info->egid) !=
          VMI_SUCCESS) {
    log_debug("Failed to read credential values");
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
  // Note: Process identifier at https://elixir.bootlin.com/linux/v6.16.3/source/include/linux/sched.h#L100
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

  log_debug("PID %u: %s [%s] [%s] (task_struct=0x%" PRIx64 ")", proc_info->pid,
            proc_info->name, thread_type, state_str,
            proc_info->task_struct_addr);

  if (!proc_info->is_kernel_thread) {
    log_debug("Credentials: uid=%u gid=%u euid=%u egid=%u", proc_info->uid,
              proc_info->gid, proc_info->euid, proc_info->egid);
  }
}

// NOLINTNEXTLINE
uint32_t state_process_list_callback(vmi_instance_t vmi, void* context) {
  // Preconditions
  if (!vmi || !context) {
    log_error("STATE_PROCESS_LIST: Invalid input parameters.");
    return VMI_FAILURE;
  }
  event_handler_t* event_handler = (event_handler_t*)context;
  if (!event_handler || !event_handler->is_paused) {
    log_error("STATE_PROCESS_LIST: Callback requires a paused VM.");
    return VMI_FAILURE;
  }

  log_info("Executing STATE_PROCESS_LIST_CALLBACK callback.");

  addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
  addr_t current_process = 0;
  process_info_t proc_info = {0};

  uint32_t total_processes = 0, kernel_threads = 0, user_processes = 0;

  if (vmi_translate_ksym2v(vmi, "init_task", &list_head) != VMI_SUCCESS) {
    log_error("STATE_PROCESS_LIST: Failed to resolve init_task");
    return VMI_FAILURE;
  }

  unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0,
                mm_offset = 0, linux_tasks_offset = 0;

  if (vmi_get_offset(vmi, "linux_tasks", &linux_tasks_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_pid", &pid_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_name", &name_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_mm", &mm_offset) != VMI_SUCCESS) {

    log_error(
        "STATE_PROCESS_LIST: Failed to retrieve required task_struct "
        "offsets from profile");
    return VMI_FAILURE;
  }

  list_head += linux_tasks_offset;

  if (vmi_read_addr_va(vmi, list_head, 0, &next_list_entry) != VMI_SUCCESS) {
    log_error("STATE_PROCESS_LIST: Failed to read first task pointer");
    return VMI_FAILURE;
  }

  log_info("STATE_PROCESS_LIST: Starting kernel task list walk...");
  cur_list_entry = list_head;

  do {
    memset(&proc_info, 0, sizeof(proc_info));
    current_process = cur_list_entry - tasks_offset;
    proc_info.task_struct_addr = current_process;
    bool process_valid = true;

    // Read PID
    if (vmi_read_32_va(vmi, current_process + pid_offset, 0,
                       (uint32_t*)&proc_info.pid) != VMI_SUCCESS) {
      log_warn("STATE_PROCESS_LIST: Failed to read PID at 0x%" PRIx64,
               current_process);
      process_valid = false;
    }

    // Read process name
    if (process_valid) {
      proc_info.name = vmi_read_str_va(vmi, current_process + name_offset, 0);
      if (!proc_info.name) {
        log_warn(
            "STATE_PROCESS_LIST: Failed to read process name for PID "
            "%u",
            proc_info.pid);
        process_valid = false;
      }
    }

    // Read process state
    if (process_valid) {
      if (vmi_read_32_va(vmi, current_process + LINUX_STATE_OFFSET, 0,
                         &proc_info.state) != VMI_SUCCESS) {
        log_warn(
            "STATE_PROCESS_LIST: Failed to read process state for PID "
            "%u",
            proc_info.pid);
        // Unknown state.
        proc_info.state = 0xFFFFFFFF;
      }

      proc_info.is_kernel_thread =
          is_kernel_thread(vmi, current_process, mm_offset);

      if (!proc_info.is_kernel_thread) {
        if (!read_process_credentials(vmi, current_process, LINUX_CRED_OFFSET,
                                      &proc_info)) {
          log_warn(
              "STATE_PROCESS_LIST: Failed to read credentials for PID "
              "%u",
              proc_info.pid);
          // Continue anyway, just mark credentials as invalid.
          proc_info.uid = proc_info.gid = proc_info.euid = proc_info.egid =
              0xFFFFFFFF;
        }
        user_processes++;
      } else {
        kernel_threads++;
      }

      print_process_info(&proc_info);
      total_processes++;
    }

    if (proc_info.name) {
      g_free(proc_info.name);
      proc_info.name = NULL;
    }

    if (vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry) !=
        VMI_SUCCESS) {
      log_error(
          "STATE_PROCESS_LIST: Failed to read next task pointer at "
          "0x%" PRIx64,
          cur_list_entry);
      return VMI_FAILURE;
    }

    cur_list_entry = next_list_entry;

  } while (cur_list_entry != list_head);

  log_info("STATE_PROCESS_LIST: Finished walking kernel task list");
  log_info(
      "STATE_PROCESS_LIST: Summary: %u total processes (%u user, %u "
      "kernel threads)",
      total_processes, user_processes, kernel_threads);

  log_info("STATE_PROCESS_LIST_CALLBACK callback completed.");
  return VMI_SUCCESS;
}
