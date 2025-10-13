#include "state_callbacks/process_list.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <string.h>
#include "event_handler.h"
#include "offsets.h"
#include "state_callbacks/responses/process_list_response.h"
#include "utils.h"

/**
 * @brief Local structure to hold process information during enumeration.
 */
typedef struct {
  vmi_pid_t pid;                  ///< Process ID.
  char* name;                     ///< Process name (comm).
  addr_t task_struct_addr;        ///< Address of the task_struct.
  uint32_t uid, gid, euid, egid;  ///< Credentials.
  uint32_t state;                 ///< Process state.
  bool is_kernel_thread;          ///< Flag indicating if it's a kernel thread.
  addr_t mm_addr;                 ///<  Memory management struct.
} local_process_info_t;

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
/**
 * @brief Convert process state value to character representation
 * 
 * @param state Process state value from task_struct
 * @return char Character representing the state
 * 
 * @details State mappings:
 *  0 (TASK_RUNNING)            -> 'R'
 *  1 (TASK_INTERRUPTIBLE)      -> 'S'
 *  2 (TASK_UNINTERRUPTIBLE)    -> 'D'
 *  4 (TASK_STOPPED)            -> 'T'
 *  8 (TASK_TRACED)             -> 't'
 *  16 (TASK_ZOMBIE)            -> 'Z'
 *  32 (TASK_DEAD)              -> 'X'
 *  Other                       -> '?'
 */
static char get_process_state_char(uint32_t state) {
  switch (state) {
    case 0:
      return 'R';  // TASK_RUNNING
    case 1:
      return 'S';  // TASK_INTERRUPTIBLE
    case 2:
      return 'D';  // TASK_UNINTERRUPTIBLE
    case 4:
      return 'T';  // TASK_STOPPED
    case 8:
      return 't';  // TASK_TRACED
    case 16:
      return 'Z';  // TASK_ZOMBIE
    case 32:
      return 'X';  // TASK_DEAD
    default:
      return '?';  // UNKNOWN
  }
}

/**
 * @brief Convert process state value to string representation
 * 
 * @param state Process state value from task_struct
 * @return const char* String representing the state
 * 
 * @details State mappings (see TASK_* defines in linux/sched.h):
 *  0 (TASK_RUNNING)            -> "RUNNING"
 *  1 (TASK_INTERRUPTIBLE)      -> "INTERRUPTIBLE"
 *  2 (TASK_UNINTERRUPTIBLE)    -> "UNINTERRUPTIBLE"
 *  4 (TASK_STOPPED)            -> "STOPPED"
 *  8 (TASK_TRACED)             -> "TRACED"
 *  16 (TASK_ZOMBIE)            -> "ZOMBIE"
 *  32 (TASK_DEAD)              -> "DEAD"
 *  Other                       -> "UNKNOWN"
 */
static const char* get_process_state_string(uint32_t state) {
  switch (state) {
    case 0:
      return "RUNNING";
    case 1:
      return "INTERRUPTIBLE";
    case 2:
      return "UNINTERRUPTIBLE";
    case 4:
      return "STOPPED";
    case 8:
      return "TRACED";
    case 16:
      return "ZOMBIE";
    case 32:
      return "DEAD";
    default:
      return "UNKNOWN";
  }
}

static bool is_kernel_thread(vmi_instance_t vmi, addr_t task_struct,
                             unsigned long mm_offset) {
  addr_t mm_addr = 0;
  if (vmi_read_addr_va(vmi, task_struct + mm_offset, 0, &mm_addr) !=
      VMI_SUCCESS) {
    log_debug("STATE_PROCESS_LIST: Failed to read mm field at 0x%" PRIx64,
              task_struct);
    return false;
  }

  return (mm_addr == 0);
}

static bool read_process_credentials(vmi_instance_t vmi, addr_t task_struct,
                                     unsigned long cred_offset,
                                     local_process_info_t* proc_info) {
  addr_t cred_addr = 0;
  if (vmi_read_addr_va(vmi, task_struct + cred_offset, 0, &cred_addr) !=
      VMI_SUCCESS) {
    log_debug("STATE_PROCESS_LIST: Failed to read credentials pointer");
    return false;
  }

  if (cred_addr == 0) {
    log_debug("NULL credentials pointer");
    return false;
  }

  // Read credentials.
  // See: https://docs.kernel.org/security/credentials.html.
  if (vmi_read_32_va(vmi, cred_addr + LINUX_UID_OFFSET, 0, &proc_info->uid) !=
          VMI_SUCCESS ||
      vmi_read_32_va(vmi, cred_addr + LINUX_GID_OFFSET, 0, &proc_info->gid) !=
          VMI_SUCCESS ||
      vmi_read_32_va(vmi, cred_addr + LINUX_EUID_OFFSET, 0, &proc_info->euid) !=
          VMI_SUCCESS ||
      vmi_read_32_va(vmi, cred_addr + LINUX_EGID_OFFSET, 0, &proc_info->egid) !=
          VMI_SUCCESS) {
    log_debug("STATE_PROCESS_LIST: Failed to read credential values");
    return false;
  }

  return true;
}

/**
 * @brief Print process information.
 *
 * @param proc_info Pointer to the local_process_info_t structure containing process details.
 */
static void print_process_info(const local_process_info_t* proc_info) {
  const char* thread_type = proc_info->is_kernel_thread ? "KERNEL" : "USER";
  const char* state_str = get_process_state_string(proc_info->state);

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
    return log_error_and_queue_response_task(
        "process_list_state", STATE_PROCESS_LIST, INVALID_ARGUMENTS,
        "STATE_PROCESS_LIST: Invalid arguments to process list state "
        "callback.");
  }
  event_handler_t* event_handler = (event_handler_t*)context;
  if (!event_handler || !event_handler->is_paused) {
    return log_error_and_queue_response_task(
        "process_list_state", STATE_PROCESS_LIST, INVALID_ARGUMENTS,
        "STATE_PROCESS_LIST: Callback requires a valid event handler context.");
  }

  log_info("Executing STATE_PROCESS_LIST callback.");

  // Create process list state data structure
  process_list_state_data_t* process_data = process_list_state_data_new();
  if (!process_data) {
    return log_error_and_queue_response_task(
        "process_list_state", STATE_PROCESS_LIST, MEMORY_ALLOCATION_FAILURE,
        "STATE_PROCESS_LIST: Failed to allocate memory for process list state "
        "data.");
  }

  addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
  addr_t current_process = 0;
  local_process_info_t proc_info = {0};

  uint32_t total_processes = 0, kernel_threads = 0, user_processes = 0;

  if (vmi_translate_ksym2v(vmi, "init_task", &list_head) != VMI_SUCCESS) {
    process_list_state_data_free(process_data);
    return log_error_and_queue_response_task(
        "process_list_state", STATE_PROCESS_LIST, VMI_OP_FAILURE,
        "STATE_PROCESS_LIST: Failed to resolve init_task");
  }

  unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0,
                mm_offset = 0, linux_tasks_offset = 0;

  if (vmi_get_offset(vmi, "linux_tasks", &linux_tasks_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_pid", &pid_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_name", &name_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_mm", &mm_offset) != VMI_SUCCESS) {
    process_list_state_data_free(process_data);
    return log_error_and_queue_response_task(
        "process_list_state", STATE_PROCESS_LIST, VMI_OP_FAILURE,
        "STATE_PROCESS_LIST: Failed to retrieve required task_struct offsets "
        "from profile");
  }

  list_head += linux_tasks_offset;

  if (vmi_read_addr_va(vmi, list_head, 0, &next_list_entry) != VMI_SUCCESS) {
    process_list_state_data_free(process_data);
    return log_error_and_queue_response_task(
        "process_list_state", STATE_PROCESS_LIST, VMI_OP_FAILURE,
        "STATE_PROCESS_LIST: Failed to read first task pointer");
  }

  // Set page size (assuming 4KB for now, could be made configurable)
  uint32_t page_size = 4096;
  process_list_state_set_basic_info(process_data, page_size, 0);

  log_info("STATE_PROCESS_LIST: Starting kernel task list walk...");
  cur_list_entry = list_head;

  do {
    memset(&proc_info, 0, sizeof(proc_info));
    current_process = cur_list_entry - linux_tasks_offset;
    proc_info.task_struct_addr = current_process;
    bool process_valid = true;

    // Read PID
    if (vmi_read_32_va(vmi, current_process + pid_offset, 0,
                       (uint32_t*)&proc_info.pid) != VMI_SUCCESS) {
      log_debug("STATE_PROCESS_LIST: Failed to read PID at 0x%" PRIx64,
                current_process);
      process_valid = false;
    }

    // Read process name
    if (process_valid) {
      proc_info.name = vmi_read_str_va(vmi, current_process + name_offset, 0);
      if (!proc_info.name) {
        log_debug(
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
        log_debug(
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
          log_debug(
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

      // Add process to data structure
      process_credentials_t credentials = {.uid = proc_info.uid,
                                           .gid = proc_info.gid,
                                           .euid = proc_info.euid,
                                           .egid = proc_info.egid};

      // Convert state to character representation
      char state_char = get_process_state_char(proc_info.state);

      process_list_state_add_process(
          process_data, proc_info.pid, proc_info.name, state_char,
          proc_info.task_struct_addr, proc_info.is_kernel_thread,
          proc_info.is_kernel_thread ? NULL : &credentials);

      total_processes++;
    }

    if (proc_info.name) {
      g_free(proc_info.name);
      proc_info.name = NULL;
    }

    if (vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry) !=
        VMI_SUCCESS) {
      process_list_state_data_free(process_data);
      return log_error_and_queue_response_task(
          "process_list_state", STATE_PROCESS_LIST, VMI_OP_FAILURE,
          "STATE_PROCESS_LIST: Failed to read next task pointer");
    }

    cur_list_entry = next_list_entry;

  } while (cur_list_entry != list_head);

  // Update count and set summary
  process_list_state_set_basic_info(process_data, page_size, total_processes);
  process_list_state_set_summary(process_data, total_processes, user_processes,
                                 kernel_threads);

  log_info("STATE_PROCESS_LIST: Finished walking kernel task list");
  log_info(
      "STATE_PROCESS_LIST: Summary: %u total processes (%u user, %u "
      "kernel threads)",
      total_processes, user_processes, kernel_threads);

  log_info("STATE_PROCESS_LIST callback completed.");
  return log_success_and_queue_response_task(
      "process_list_state", STATE_PROCESS_LIST, process_data,
      (void (*)(void*))process_list_state_data_free);
}
