#include "dispatcher.h"
#include <log.h>

const char* state_task_id_to_str(state_task_id_t task_id) {
  switch (task_id) {
    case STATE_KERNEL_MODULE_LIST:
      return "KERNEL_MODULE_LIST";
    case STATE_FTRACE_HOOKS:
      return "FTRACE_HOOKS";
    case STATE_NETWORK_TRACE:
      return "NETWORK_TRACE";
    case STATE_SYSCALL_TABLE:
      return "SYSCALL_TABLE";
    case STATE_IDT_TABLE:
      return "IDT_TABLE";
    case STATE_DIR_STRING_MATCHING:
      return "DIR_STRING_MATCHING";
    case STATE_PROCESS_LIST:
      return "PROCESS_LIST";
    case STATE_PROCFS_ARTIFACTS:
      return "PROCFS_ARTIFACTS";
    case STATE_NETFILTER_HOOKS:
      return "NETFILTER_HOOKS";
    case STATE_KERNEL_THREADS:
      return "KERNEL_THREADS";
    case STATE_KPROBES_JPROBES_KRETPROBES:
      return "KPROBES_JPROBES_KRETPROBES";
    case STATE_MSR_REGISTERS:
      return "MSR_REGISTERS";
    case STATE_KERNEL_CODE_INTEGRITY_CHECK:
      return "KERNEL_CODE_INTEGRITY_CHECK";
    case STATE_EBPF_ARTIFACTS:
      return "EBPF_ARTIFACTS";
    case STATE_IO_URING_ARTIFACTS:
      return "IO_URING_ARTIFACTS";
    case STATE_CREDENTIALS:
      return "CREDENTIALS";
    case STATE_KALLSYMS_SYMBOLS:
      return "KALLSYMS_SYMBOLS";
    case STATE_FIRMWARE_ACPI_HOOKS:
      return "FIRMWARE_ACPI_HOOKS";
    default:
      log_error("Unknown state task with code: %d", task_id);
      return "UNKNOWN_STATE_TASK";
  }
}

const char* event_task_id_to_str(event_task_id_t task_id) {
  switch (task_id) {
    case EVENT_FTRACE_PATCHING:
      return "FTRACE_PATCHING";
    case EVENT_SYSCALL_TABLE_WRITE:
      return "SYSCALL_TABLE_WRITE";
    case EVENT_IDT_ENTRY_MODIFICATION:
      return "IDT_ENTRY_MODIFICATION";
    case EVENT_CR0_WRITE:
      return "CR0_WRITE";
    case EVENT_PAGE_TABLE_MODIFICATION:
      return "PAGE_TABLE_MODIFICATION";
    case EVENT_NETFILTER_HOOK_WRITE:
      return "NETFILTER_HOOK_WRITE";
    case EVENT_MSR_WRITE:
      return "MSR_WRITE";
    case EVENT_CODE_SECTION_MODIFY:
      return "CODE_SECTION_MODIFY";
    case EVENT_INTROSPECTION_INTEGRITY:
      return "INTROSPECTION_INTEGRITY";
    case EVENT_IO_URING_RING_WRITE:
      return "IO_URING_RING_WRITE";
    case EVENT_EBPF_MAP_UPDATE:
      return "EBPF_MAP_UPDATE";
    case EVENT_KALLSYMS_TABLE_WRITE:
      return "KALLSYMS_TABLE_WRITE";
    default:
      log_error("Unknown event task with code: %d", task_id);
      return "UNKNOWN_EVENT_TASK";
  }
}

dispatcher_t* dispatcher_initialize(vmi_instance_t vmi) {
  // Note: Attempts to allocate n_bytes, initialized to 0’s, and returns NULL on failure.
  // Contrast with g_malloc0(), which aborts the program on failure.
  // See: https://docs.gtk.org/glib/func.try_malloc0.html
  dispatcher_t* dispatcher = g_malloc0(sizeof(dispatcher_t));

  dispatcher->vmi = vmi;
  g_mutex_init(&dispatcher->vm_mutex);

  // Initialize with placeholder values.
  for (int i = 0; i < STATE_TASK_ID_MAX; ++i)
    dispatcher->state_tasks[i] = NULL;

  for (int i = 0; i < EVENT_TASK_ID_MAX; ++i)
    dispatcher->event_tasks[i] = NULL;

  dispatcher->state_thread = NULL;
  dispatcher->event_thread = NULL;

  return dispatcher;
}

void dispatcher_free(dispatcher_t* dispatcher) {
  if (!dispatcher) {
    log_warn("The provided dispatcher to be freed is NULL.");
    return;
  }

  for (int i = 0; i < STATE_TASK_ID_MAX; ++i) {
    state_task_t* task = dispatcher->state_tasks[i];
    if (task) {
      // TODO: Free nested resources.
      g_free(task);
    }
  }

  for (int i = 0; i < EVENT_TASK_ID_MAX; ++i) {
    event_task_t* task = dispatcher->event_tasks[i];
    if (task) {
      vmi_clear_event(dispatcher->vmi, &task->filter, NULL);
      // Note: The event is removed from hashtables internal to LibVMI,
      // but the memory related to the vmi_event_t is not freed
      // Memory management remains the responsibility of the caller.
      // TODO: Free nested resources.
      g_free(task);
    }
  }

  g_mutex_clear(&dispatcher->vm_mutex);
  g_free(dispatcher);
}

void dispatcher_register_state_task(dispatcher_t* dispatcher,
                                    state_task_id_t task_id, double interval_ms,
                                    void* context,
                                    void (*callback)(vmi_instance_t, void*)) {

  // Top level checks
  if (!dispatcher) {
    log_error("The provided dispatcher is NULL.");
    return;
  }

  if (task_id >= STATE_TASK_ID_MAX) {
    log_error("Invalid state task ID: %d", task_id);
    return;
  }

  state_task_t* task = g_malloc0(sizeof(state_task_t));

  task->id = task_id;
  task->interval_ms = interval_ms;
  task->last_invoked_time = 0.0;
  task->context = context;
  task->callback = callback;

  dispatcher->state_tasks[task_id] = task;
}

void dispatcher_register_event_task(
    dispatcher_t* dispatcher, event_task_id_t task_id, vmi_event_t filter,
    void* context, void (*callback)(vmi_instance_t, vmi_event_t*, void*)) {

  // Top level checks
  if (!dispatcher) {
    log_error("The provided dispatcher is NULL.");
    return;
  }

  if (task_id >= EVENT_TASK_ID_MAX) {
    log_error("Invalid event task ID: %d", task_id);
    return;
  }

  event_task_t* task = g_malloc0(sizeof(event_task_t));

  task->id = task_id;
  task->filter = filter;
  task->context = context;
  task->callback = callback;
  task->event_count = 0;

  // Set the callback in LibVMI event
  task->filter.callback = callback;

  dispatcher->event_tasks[task_id] = task;

  vmi_register_event(dispatcher->vmi, &task->filter);
}