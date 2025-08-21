#include "event_handler.h"
#include <inttypes.h>
#include <log.h>

const char* state_task_id_to_str(state_task_id_t task_id) {
  switch (task_id) {
    case STATE_KERNEL_MODULE_LIST:
      return "STATE_KERNEL_MODULE_LIST";
    case STATE_FTRACE_HOOKS:
      return "STATE_FTRACE_HOOKS";
    case STATE_NETWORK_TRACE:
      return "STATE_NETWORK_TRACE";
    case STATE_SYSCALL_TABLE:
      return "STATE_SYSCALL_TABLE";
    case STATE_IDT_TABLE:
      return "STATE_IDT_TABLE";
    case STATE_DIR_STRING_MATCHING:
      return "STATE_DIR_STRING_MATCHING";
    case STATE_PROCESS_LIST:
      return "STATE_PROCESS_LIST";
    case STATE_MSR_REGISTERS:
      return "STATE_MSR_REGISTERS";
    case STATE_KERNEL_CODE_INTEGRITY_CHECK:
      return "STATE_KERNEL_CODE_INTEGRITY_CHECK";
    case STATE_EBPF_ARTIFACTS:
      return "STATE_EBPF_ARTIFACTS";
    case STATE_IO_URING_ARTIFACTS:
      return "STATE_IO_URING_ARTIFACTS";
    case STATE_KALLSYMS_SYMBOLS:
      return "STATE_KALLSYMS_SYMBOLS";
    default:
      log_error("Unknown state task with code: %d", task_id);
      return NULL;
  }
}

const char* event_task_id_to_str(event_task_id_t task_id) {
  switch (task_id) {
    case EVENT_FTRACE_PATCHING:
      return "EVENT_FTRACE_PATCHING";
    case EVENT_SYSCALL_TABLE_WRITE:
      return "EVENT_SYSCALL_TABLE_WRITE";
    case EVENT_IDT_ENTRY_MODIFICATION:
      return "EVENT_IDT_ENTRY_MODIFICATION";
    case EVENT_CR0_WRITE:
      return "EVENT_CR0_WRITE";
    case EVENT_PAGE_TABLE_MODIFICATION:
      return "EVENT_PAGE_TABLE_MODIFICATION";
    case EVENT_NETFILTER_HOOK_WRITE:
      return "EVENT_NETFILTER_HOOK_WRITE";
    case EVENT_MSR_WRITE:
      return "EVENT_MSR_WRITE";
    case EVENT_CODE_SECTION_MODIFY:
      return "EVENT_CODE_SECTION_MODIFY";
    case EVENT_INTROSPECTION_INTEGRITY:
      return "EVENT_INTROSPECTION_INTEGRITY";
    case EVENT_IO_URING_RING_WRITE:
      return "EVENT_IO_URING_RING_WRITE";
    case EVENT_EBPF_MAP_UPDATE:
      return "EVENT_EBPF_MAP_UPDATE";
    case EVENT_KALLSYMS_TABLE_WRITE:
      return "EVENT_KALLSYMS_TABLE_WRITE";
    default:
      log_error("Unknown event task with code: %d", task_id);
      return NULL;
  }
}

int state_task_id_from_str(const char* str) {
  if (!str) {
    log_error("The provided string to convert to state task ID is NULL.");
    return -1;
  }

  for (int i = 0; i < STATE_TASK_ID_MAX; ++i) {
    if (strcmp(str, state_task_id_to_str(i)) == 0)
      return i;
  }
  log_error("Unknown state task ID string: %s", str);
  return -1;
}

int event_task_id_from_str(const char* str) {
  if (!str) {
    log_error("The provided string to convert to event task ID is NULL.");
    return -1;
  }

  for (int i = 0; i < EVENT_TASK_ID_MAX; ++i) {
    if (strcmp(str, event_task_id_to_str(i)) == 0)
      return i;
  }
  log_error("Unknown event task ID string: %s", str);
  return -1;
}

event_handler_t* event_handler_initialize(vmi_instance_t vmi,
                                          uint32_t window_ms,
                                          uint32_t state_sampling_ms) {

  if (vmi == NULL) {
    log_error("The provided VMI instance is NULL.");
    return NULL;
  }

  // Note: Attempts to allocate n_bytes, initialized to 0’s, and returns NULL on failure.
  // Contrast with g_malloc0(), which aborts the program on failure.
  // See: https://docs.gtk.org/glib/func.try_malloc0.html
  event_handler_t* event_handler = g_new0(event_handler_t, 1);

  event_handler->window_ms = window_ms;
  event_handler->state_sampling_ms = state_sampling_ms;
  event_handler->vmi = vmi;
  // Initialize with timestamp when the first task state sampling is performed.
  // 0 is a placeholder value, indicating that no state sampling has been performed yet.
  event_handler->latest_state_sampling_ms = 0;

  // Initialize with placeholder values.
  for (int i = 0; i < STATE_TASK_ID_MAX; ++i)
    event_handler->state_tasks[i] = NULL;

  for (int i = 0; i < EVENT_TASK_ID_MAX; ++i)
    event_handler->event_tasks[i] = NULL;

  // Create new queue for event callbacks.
  return event_handler;
}

void event_handler_free(event_handler_t* event_handler) {
  if (!event_handler) {
    log_warn("The provided event_handler to be freed is NULL.");
    return;
  }

  for (int i = 0; i < STATE_TASK_ID_MAX; ++i) {
    state_task_t* task = event_handler->state_tasks[i];
    g_free(task);
  }

  for (int i = 0; i < EVENT_TASK_ID_MAX; ++i) {
    event_task_t* task = event_handler->event_tasks[i];
    if (task) {
      vmi_clear_event(event_handler->vmi, task->event, NULL);
      // Note: The event is removed from hashtables internal to LibVMI,
      // but the memory related to the vmi_event_t is not freed.
      // Memory management remains the responsibility of the caller.
      g_free(task->event);
      g_free(task);
    }
  }

  g_free(event_handler);
}

void event_handler_register_state_task(event_handler_t* event_handler,
                                       state_task_id_t task_id,
                                       uint32_t (*functor)(vmi_instance_t,
                                                           void*)) {

  if (!event_handler) {
    log_error("The provided event_handler is NULL.");
    return;
  }

  if (task_id >= STATE_TASK_ID_MAX) {
    log_error("Invalid state task ID: %d", task_id);
    return;
  }

  state_task_t* task = g_new0(state_task_t, 1);

  task->id = task_id;
  task->functor = functor;

  // TODO: Each task_id should be associated with a specific functor (callback).
  event_handler->state_tasks[task_id] = task;
}

void event_handler_register_event_task(
    event_handler_t* event_handler, event_task_id_t task_id, vmi_event_t* event,
    event_response_t (*callback)(vmi_instance_t, vmi_event_t*)) {
  // Note: Each event will have its own create_event_EVENT_TASK_ID function
  // that will set the event type, flags, and other parameters.

  if (!event_handler) {
    log_error("The provided event_handler is NULL.");
    return;
  }

  if (task_id >= EVENT_TASK_ID_MAX) {
    log_error("Invalid event task ID: %d", task_id);
    return;
  }

  if (!event) {
    log_error("The provided event is NULL.");
    return;
  }

  event_task_t* task = g_new0(event_task_t, 1);

  task->id = task_id;
  task->event = event;
  task->event_count = 0;

  // Set the callback and data in the LibVMI event struct.
  task->event->callback = callback;
  task->event->data = task;

  event_handler->event_tasks[task_id] = task;

  vmi_register_event(event_handler->vmi, task->event);
}

void event_handler_start_event_loop(event_handler_t* event_handler) {
  if (!event_handler) {
    log_error("The provided event_handler is NULL.");
    return;
  }

  event_handler->event_thread =
      g_thread_new("event_loop", (GThreadFunc)event_loop_thread, event_handler);
}

static gpointer event_loop_thread(gpointer data) {
  if (!data) {
    log_error("The provided data to the event loop thread is NULL.");
    return NULL;
  }

  event_handler_t* event_handler = (event_handler_t*)data;
  log_info("Pre-sampling state tasks before starting the event loop thread...");
  sample_state_tasks(event_handler);
  log_info("Starting event loop thread with window size: %u ms",
           event_handler->window_ms);
  while (true) {
    // NOTE: LibVMI processes one event at a time, listen to total of time window_ms.
    // The callback will be triggered, which will enqueue the item.
    vmi_events_listen(event_handler->vmi, event_handler->window_ms);
  }
  log_info("Event loop thread has finished processing events, exiting...");
  log_info(
      "Post-sampling state tasks after the event loop thread has started...");
  return NULL;
}

void sample_state_tasks(event_handler_t* event_handler) {
  if (!event_handler) {
    log_error("The provided event_handler is NULL.");
    return;
  }

  // Check if the time since the last state sampling exceeds the configured interval.
  uint64_t current_time_ms = g_get_monotonic_time() / 1000;
  if (current_time_ms - event_handler->latest_state_sampling_ms <
      event_handler->state_sampling_ms) {
    log_warn(
        "State sampling skipped, "
        "not enough time has passed since the last sampling: "
        "%" PRIu64 " ms",
        current_time_ms - event_handler->latest_state_sampling_ms);
    return;
  }

  // TODO (improvement): State sampling if accessing separate kernel data structures could be split to threads.
  // This would definitely be a performance issue.
  for (int i = 0; i < STATE_TASK_ID_MAX; ++i) {
    state_task_t* task = event_handler->state_tasks[i];
    if (task && task->functor) {
      task->functor(event_handler->vmi, NULL);
    }
  }

  event_handler->latest_state_sampling_ms = current_time_ms;
}