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
      return NULL;
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

dispatcher_t* dispatcher_initialize(vmi_instance_t vmi, uint32_t window_ms,
                                    uint32_t state_sample_interval_ms) {
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

  // Create new queue for event callbacks.
  dispatcher->event_queue = g_async_queue_new();

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
                                    state_task_id_t task_id, void* context,
                                    uint32_t (*callback)(vmi_instance_t,
                                                         void*)) {

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
  task->last_invoked_time = 0;
  task->context = context;
  task->callback = callback;

  dispatcher->state_tasks[task_id] = task;
}

void dispatcher_register_event_task(
    dispatcher_t* dispatcher, event_task_id_t task_id, vmi_event_t filter,
    event_response_t (*callback)(vmi_instance_t, vmi_event_t*)) {

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
  // Context is the event_task itself, which is passed to the vmi_event.
  task->callback = callback;
  task->event_count = 0;

  // Set the callback and data in the LibVMI event struct.
  task->filter.callback = callback;
  task->filter.data = task;

  dispatcher->event_tasks[task_id] = task;

  vmi_register_event(dispatcher->vmi, &task->filter);
}

void dispatcher_start_state_loop(dispatcher_t* dispatcher) {
  if (!dispatcher) {
    log_error("The provided dispatcher is NULL.");
    return;
  }

  // Create and start the state loop thread.
  dispatcher->state_thread =
      g_thread_new("state_loop", (GThreadFunc)state_loop_thread, dispatcher);
}

void dispatcher_start_event_loop(dispatcher_t* dispatcher) {
  if (!dispatcher) {
    log_error("The provided dispatcher is NULL.");
    return;
  }

  // Create and start the event loop thread.
  dispatcher->event_thread =
      g_thread_new("event_loop", (GThreadFunc)event_loop_thread, dispatcher);
}

void dispatcher_start_event_worker(dispatcher_t* dispatcher) {
  if (!dispatcher) {
    log_error("The provided dispatcher is NULL.");
    return;
  }

  dispatcher->event_worker_thread = g_thread_new(
      "event_worker", (GThreadFunc)event_worker_thread, dispatcher);
}

static gpointer event_loop_thread(gpointer data) {
  if (!data) {
    log_error("The provided data to the event loop thread is NULL.");
    return NULL;
  }

  dispatcher_t* dispatcher = (dispatcher_t*)data;

  while (true) {
    // NOTE: LibVMI processes one event at a time, listen to total of time window_ms.
    // The callback will be triggered, which will enqueue the item.
    vmi_events_listen(dispatcher->vmi, dispatcher->window_ms);
  }

  return NULL;
}

static gpointer state_loop_thread(gpointer data) {
  if (!data) {
    log_error("The provided data to the state loop thread is NULL.");
    return NULL;
  }

  dispatcher_t* dispatcher = (dispatcher_t*)data;

  const uint64_t start_time_ms =
      g_get_monotonic_time() / 1000;  // Start of window

  while (true) {
    const uint64_t loop_start_ms = g_get_monotonic_time() / 1000;

    // Check if we exceeded the monitoring window duration
    if ((loop_start_ms - start_time_ms) >= dispatcher->window_ms) {
      log_info("State loop has completed its monitoring window (%u ms).",
               dispatcher->window_ms);
      break;
    }

    // Acquire the VM mutex once to ensure a consistent state across all callbacks.
    g_mutex_lock(&dispatcher->vm_mutex);

    for (int i = 0; i < STATE_TASK_ID_MAX; ++i) {
      state_task_t* task = dispatcher->state_tasks[i];
      if (!task)
        continue;

      task->callback(dispatcher->vmi, task->context);

      // Optionally update last_invoked_time if needed (not used in fixed-rate logic)
      task->last_invoked_time = loop_start_ms;
    }

    g_mutex_unlock(&dispatcher->vm_mutex);

    // Compute how long the loop iteration took.
    const uint64_t loop_end_ms = g_get_monotonic_time() / 1000;
    const uint64_t elapsed_ms = loop_end_ms - loop_start_ms;

    // Compute the remaining time to sleep to maintain fixed rate.
    if (elapsed_ms < dispatcher->state_sampling_ms) {
      const uint64_t sleep_ms = dispatcher->state_sampling_ms - elapsed_ms;
      // Convert ms to µs
      g_usleep(sleep_ms * 1000);
    } else {
      // This can happen when the lock is held for too long or the callback takes too long.
      log_warn("State sampling loop overran its interval (%u ms).",
               dispatcher->state_sampling_ms);
    }
  }

  return NULL;
}

static gpointer event_worker_thread(gpointer data) {
  if (!data) {
    log_error("The provided data to the event worker thread is NULL.");
    return NULL;
  }

  dispatcher_t* dispatcher = (dispatcher_t*)data;

  while (true) {
    // Block until an event item is available in the queue.
    callback_event_item_t* item = g_async_queue_pop(dispatcher->event_queue);

    if (!item || !item->task) {
      log_error("Invalid callback event item.");
      g_free(item);
      continue;
    }

    // We restrain the number of runs for an event task to not overload logs.
    if (item->task->event_count >= EVENT_TASK_COUNT) {
      if (item->task->event_count == EVENT_TASK_COUNT) {
        log_warn(
            "Event task %s reached limit of runs, skipping further callbacks.",
            event_task_id_to_str(item->task->id));
      }

      // Continue tracking how many times it would have been called.
      item->task->event_count++;
      g_free(item);
      continue;
    }

    g_mutex_lock(&dispatcher->vm_mutex);

    item->task->event_count++;

    // Call the callback function with the VMI instance and event.
    // There may be pausing logic here in the callback if needed.
    item->task->callback(dispatcher->vmi, &item->event);

    g_mutex_unlock(&dispatcher->vm_mutex);

    g_free(item);
  }

  return NULL;
}
