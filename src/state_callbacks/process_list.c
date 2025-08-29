#include "state_callbacks/process_list.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <string.h>

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

// Offsets are retrieved from the LibVMI profile at runtime. They were extracted with pahole from the vmlinux file.
static unsigned long state_offset = 0;  ///< unsigned int __state
static unsigned long tasks_offset = 0;  ///< struct list_head tasks
static unsigned long mm_offset = 0;     ///< struct mm_struct *mm
static unsigned long pid_offset = 0;    ///< pid_t pid
static unsigned long cred_offset = 0;   ///< const struct cred *cred
static unsigned long name_offset = 0;   ///< char comm[16]

static unsigned long uid_offset = 0;
static unsigned long gid_offset = 0;
static unsigned long euid_offset = 0;
static unsigned long egid_offset = 0;

/**
 * @brief Check if a task_struct represents a kernel thread.
 *
 * Kernel threads have their mm field set to NULL.
 *
 * @param vmi VMI instance.
 * @param task_struct Address of the task_struct.
 * @param mm_offset Offset of the mm field in the task_struct.
 * @return true if it is a kernel thread, false otherwise.
 */
static bool is_kernel_thread(vmi_instance_t vmi, addr_t task_struct,
                             unsigned long mm_offset) {
  addr_t mm_addr = 0;
  // Kernel threads have mm == NULL
  // Note: "tsk->mm" points to the "real address space". For an anonymous process,
  // tsk->mm will be NULL, for the logical reason that an anonymous process
  // really doesn't _have_ a real address space at all.
  // https://docs.kernel.org/mm/active_mm.html
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

  if (vmi_read_32_va(vmi, cred_addr + uid_offset, 0, &proc_info->uid) !=
          VMI_SUCCESS ||
      vmi_read_32_va(vmi, cred_addr + gid_offset, 0, &proc_info->gid) !=
          VMI_SUCCESS ||
      vmi_read_32_va(vmi, cred_addr + euid_offset, 0, &proc_info->euid) !=
          VMI_SUCCESS ||
      vmi_read_32_va(vmi, cred_addr + egid_offset, 0, &proc_info->egid) !=
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
  (void)context;

  addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
  addr_t current_process = 0;
  process_info_t proc_info = {0};

  uint32_t total_processes = 0, kernel_threads = 0, user_processes = 0;

  // Resolve required offsets from the LibVMI profile
  if (vmi_get_offset(vmi, "linux_tasks", &tasks_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_mm", &mm_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_pid", &pid_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_name", &name_offset) != VMI_SUCCESS ||
      /* NOTE: profile key is spelled 'linux_cred_offsert' */
      vmi_get_offset(vmi, "linux_cred_offsert", &cred_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_state_offset", &state_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_uid_offset", &uid_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_gid_offset", &gid_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_euid_offset", &euid_offset) != VMI_SUCCESS ||
      vmi_get_offset(vmi, "linux_egid_offset", &egid_offset) != VMI_SUCCESS) {
    log_error(
        "STATE_PROCESS_LIST_CALLBACK: Failed to retrieve required task_struct/cred offsets from profile");
    return VMI_FAILURE;
  }

  // Get init_task address
  if (vmi_translate_ksym2v(vmi, "init_task", &list_head) != VMI_SUCCESS) {
    log_error("STATE_PROCESS_LIST_CALLBACK: Failed to resolve init_task");
    return VMI_FAILURE;
  }

  list_head += tasks_offset;

  // Read first task pointer
  if (vmi_read_addr_va(vmi, list_head, 0, &next_list_entry) != VMI_SUCCESS) {
    log_error("STATE_PROCESS_LIST_CALLBACK: Failed to read first task pointer");
    return VMI_FAILURE;
  }

  log_info("STATE_PROCESS_LIST_CALLBACK: Starting kernel task list walk...");
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
      log_warn("STATE_PROCESS_LIST_CALLBACK: Failed to read PID at 0x%" PRIx64, current_process);
      process_valid = false;
    }

    // Read process name
    if (process_valid) {
      proc_info.name = vmi_read_str_va(vmi, current_process + name_offset, 0);
      if (!proc_info.name) {
        log_warn("STATE_PROCESS_LIST_CALLBACK: Failed to read process name for PID %u", proc_info.pid);
        process_valid = false;
      }
    }

    // Read process state
    if (process_valid) {
      if (vmi_read_32_va(vmi, current_process + state_offset, 0,
                         &proc_info.state) != VMI_SUCCESS) {
        log_warn("STATE_PROCESS_LIST_CALLBACK: Failed to read process state for PID %u", proc_info.pid);
        proc_info.state = 0xFFFFFFFF;  // Unknown state
      }

      // Determine if kernel thread
      proc_info.is_kernel_thread =
          is_kernel_thread(vmi, current_process, mm_offset);

      // Read credentials for user processes
      if (!proc_info.is_kernel_thread) {
        if (!read_process_credentials(vmi, current_process, cred_offset,
                                      &proc_info)) {
          log_warn("STATE_PROCESS_LIST_CALLBACK: Failed to read credentials for PID %u", proc_info.pid);
          // Continue anyway, just mark credentials as invalid
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
      log_error("STATE_PROCESS_LIST_CALLBACK: Failed to read next task pointer at 0x%" PRIx64,
                cur_list_entry);
      return VMI_FAILURE;
    }

    cur_list_entry = next_list_entry;

  } while (cur_list_entry != list_head);

  log_info("STATE_PROCESS_LIST_CALLBACK: Finished walking kernel task list");
  log_info("STATE_PROCESS_LIST_CALLBACK: Summary: %u total processes (%u user, %u kernel threads)",
           total_processes, user_processes, kernel_threads);

  return VMI_SUCCESS;
}
