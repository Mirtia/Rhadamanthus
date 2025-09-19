#include "event_handler.h"
#include <inttypes.h>
#include <log.h>
#include "event_callbacks/ebpf_tracepoint.h"
#include "event_callbacks/io_uring_ring_write.h"
#include "event_callbacks/kprobe.h"
#include "event_callbacks/network_monitor.h"

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
    case STATE_EBPF_ARTIFACTS:
      return "STATE_EBPF_ARTIFACTS";
    case STATE_IO_URING_ARTIFACTS:
      return "STATE_IO_URING_ARTIFACTS";
    case STATE_KALLSYMS_SYMBOLS:
      return "STATE_KALLSYMS_SYMBOLS";
    default:
      log_error("Unknown state task with code: %d.", task_id);
      return NULL;
  }
}

const char* event_task_id_to_str(event_task_id_t task_id) {
  switch (task_id) {
    case EVENT_FTRACE_HOOK:
      return "EVENT_FTRACE_HOOK";
    case EVENT_SYSCALL_TABLE_WRITE:
      return "EVENT_SYSCALL_TABLE_WRITE";
    case EVENT_IDT_WRITE:
      return "EVENT_IDT_WRITE";
    case EVENT_CR0_WRITE:
      return "EVENT_CR0_WRITE";
    case EVENT_PAGE_TABLE_MODIFICATION:
      return "EVENT_PAGE_TABLE_MODIFICATION";
    case EVENT_MSR_WRITE:
      return "EVENT_MSR_WRITE";
    case EVENT_CODE_SECTION_MODIFY:
      return "EVENT_CODE_SECTION_MODIFY";
    case EVENT_KALLSYMS_TABLE_WRITE:
      return "EVENT_KALLSYMS_TABLE_WRITE";
    default:
      log_error("Unknown event task with code: %d.", task_id);
      return NULL;
  }
}

const char* interrupt_task_id_to_str(interrupt_task_id_t task_id) {
  switch (task_id) {
    case INTERRUPT_KPROBE:
      return "INTERRUPT_KPROBE";
    case INTERRUPT_EBPF_TRACEPOINT:
      return "INTERRUPT_EBPF_TRACEPOINT";
    case INTERRUPT_IO_URING_RING_WRITE:
      return "INTERRUPT_IO_URING_RING_WRITE";
    case INTERRUPT_NETWORK_MONITOR:
      return "INTERRUPT_NETWORK_MONITOR";
    default:
      log_error("Unknown interrupt task with code: %d.", task_id);
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
  log_error("Unknown state task ID string: %s.", str);
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
  log_error("Unknown event task ID string: %s.", str);
  return -1;
}

int interrupt_task_id_from_str(const char* str) {
  if (!str) {
    log_error("The provided string to convert to interrupt task ID is NULL.");
    return -1;
  }

  for (int i = 0; i < INTERRUPT_TASK_ID_MAX; ++i) {
    if (strcmp(str, interrupt_task_id_to_str(i)) == 0)
      return i;
  }
  log_error("Unknown interrupt task ID string: %s.", str);
  return -1;
}

event_handler_t* event_handler_initialize(vmi_instance_t vmi,
                                          // NOLINTNEXTLINE
                                          uint32_t window_seconds,
                                          uint32_t state_sampling_seconds) {

  if (vmi == NULL) {
    log_error("The provided VMI instance is NULL.");
    return NULL;
  }

  // See: https://docs.gtk.org/glib/func.new0.html
  event_handler_t* event_handler = g_new0(event_handler_t, 1);
  if (event_handler == NULL) {
    log_error("Failed to allocate memory for event_handler.");
    return NULL;
  }

  event_handler->window_seconds = window_seconds;
  event_handler->state_sampling_seconds = state_sampling_seconds;
  event_handler->vmi = vmi;
  event_handler->stop_signal = 0;
  event_handler->stop_signal_json_serialization = 0;
  event_handler->is_paused = false;
  // Initialize with timestamp when the first task state sampling is performed.
  // 0 is a placeholder value, indicating that no state sampling has been performed yet.
  event_handler->latest_state_sampling_ms = 0;

  for (int i = 0; i < STATE_TASK_ID_MAX; ++i)
    event_handler->state_tasks[i] = NULL;

  for (int i = 0; i < EVENT_TASK_ID_MAX; ++i)
    event_handler->event_tasks[i] = NULL;

  event_handler->interrupt_context = interrupt_context_init(INITIAL_CAPACITY);
  if (!event_handler->interrupt_context) {
    log_error("Failed to initialize interrupt context.");
    g_free(event_handler);
    return NULL;
  }
  for (int i = 0; i < INTERRUPT_TASK_ID_MAX; ++i)
    event_handler->interrupt_tasks[i] = false;

  event_handler->serializer = json_serializer_new();
  json_serializer_set_global(event_handler->serializer);
  if (!event_handler->serializer) {
    log_error("Failed to create JSON serializer.");
    g_free(event_handler);
    return NULL;
  }

  return event_handler;
}

void event_handler_free(event_handler_t* event_handler) {
  if (!event_handler) {
    log_warn("The provided event_handler to be freed is NULL.");
    return;
  }

  for (int i = 0; i < STATE_TASK_ID_MAX; ++i) {
    state_task_t* task = event_handler->state_tasks[i];
    if (task) {
      g_free(task);
      event_handler->state_tasks[i] = NULL;
    }
  }

  for (int i = 0; i < EVENT_TASK_ID_MAX; ++i) {
    event_task_t* task = event_handler->event_tasks[i];
    if (!task)
      continue;

    if (task->events) {
      for (guint j = 0; j < task->events->len; ++j) {
        vmi_event_t* event = (vmi_event_t*)g_ptr_array_index(task->events, j);
        if (!event)
          continue;

        if (event_handler->vmi &&
            vmi_clear_event(event_handler->vmi, event, NULL) == VMI_FAILURE) {
          log_error("Failed to unregister event (task ID: %d, idx: %u).",
                    task->id, j);
        }
        g_free(event);
      }
      g_ptr_array_set_free_func(task->events, NULL);
      g_ptr_array_free(task->events, TRUE);
      task->events = NULL;
      // Note: The event is removed from hashtables internal to LibVMI,
      // but the memory related to the vmi_event_t is not freed.
      // Memory management remains the responsibility of the caller.
    }

    g_free(task);
    event_handler->event_tasks[i] = NULL;
  }

  if (event_handler->interrupt_context) {
    interrupt_context_cleanup(event_handler->interrupt_context,
                              event_handler->vmi);
    event_handler->interrupt_context = NULL;
    if (event_handler->global_interrupt_event) {
      vmi_clear_event(event_handler->vmi, event_handler->global_interrupt_event,
                      NULL);
      g_free(event_handler->global_interrupt_event);
      event_handler->global_interrupt_event = NULL;
    }
  }

  if (event_handler->serializer) {
    json_serializer_set_global(NULL);
    json_serializer_free(event_handler->serializer);
    event_handler->serializer = NULL;
  }

  if (event_handler->vmi) {
    vmi_destroy(event_handler->vmi);
    event_handler->vmi = NULL;
  }

  g_free(event_handler);
}

void event_handler_register_state_task(event_handler_t* event_handler,
                                       state_task_id_t task_id,
                                       uint32_t (*functor)(vmi_instance_t,
                                                           void*)) {

  // Preconditions
  if (!event_handler) {
    log_error("The provided event_handler is NULL.");
    return;
  }

  if (task_id >= STATE_TASK_ID_MAX) {
    log_error("Invalid state task ID: %d.", task_id);
    return;
  }

  state_task_t* task = g_new0(state_task_t, 1);

  task->id = task_id;
  task->functor = functor;

  event_handler->state_tasks[task_id] = task;
}

void event_handler_register_event_task(event_handler_t* event_handler,
                                       event_task_id_t task_id,
                                       GPtrArray* events) {
  // Preconditions
  if (!event_handler) {
    log_error("The provided event_handler is NULL.");
    return;
  }

  if (task_id >= EVENT_TASK_ID_MAX || task_id < 0) {
    log_error("Invalid event task ID: %d.", task_id);
    return;
  }

  if (!events || events->len == 0) {
    log_error("The provided event list is NULL or empty.");
    return;
  }

  event_task_t* task = g_new0(event_task_t, 1);
  if (!task) {
    log_error("Task allocation failed for event registration.");
    return;
  }

  task->id = task_id;
  task->events = events;
  task->event_count = 0;

  event_handler->event_tasks[task_id] = task;

  for (size_t i = 0; i < events->len; ++i) {
    vmi_event_t* event = g_ptr_array_index(events, i);
    if (event) {
      if (vmi_register_event(event_handler->vmi, event) == VMI_FAILURE) {
        log_error("Failed to register event for task ID: %d.", task_id);
      }
    }
  }
}

void event_handler_start_event_loop(event_handler_t* event_handler) {
  if (!event_handler) {
    log_error("The provided event_handler is NULL.");
    return;
  }

  event_handler->event_thread =
      g_thread_new("event_loop", (GThreadFunc)event_loop_thread, event_handler);
}

void sample_state_tasks_all(event_handler_t* event_handler) {
  if (!event_handler) {
    log_error("The provided event_handler is NULL.");
    return;
  }
  // Pause the vm for state sampling to have consistent view of the state.
  if (vmi_pause_vm(event_handler->vmi) == VMI_FAILURE) {
    log_error("Failed to pause the VM before sampling all state tasks.");
    return;
  }
  event_handler->is_paused = true;
  sample_state_tasks(event_handler);
  // Resume the vm after state sampling.
  if (vmi_resume_vm(event_handler->vmi) == VMI_FAILURE) {
    log_error("Failed to resume the VM after sampling all state tasks.");
    return;
  }
  event_handler->is_paused = false;
}

static gpointer event_loop_thread(gpointer data) {
  if (!data) {
    log_error("The provided data to the event loop thread is NULL.");
    return NULL;
  }

  event_handler_t* event_handler = (event_handler_t*)data;
  log_info("Pre-sampling state tasks before starting the event loop thread.");
  sample_state_tasks_all(event_handler);

  log_info("Starting event loop thread with window size: %u seconds.",
           event_handler->window_seconds);
  // LibVMI processes one event at a time, listen to total of time window_ms.
  // The callback will be triggered, which will enqueue the item.
  while (!g_atomic_int_get(&event_handler->stop_signal)) {
    if (vmi_events_listen(event_handler->vmi, event_handler->window_seconds *
                                                  1000) == VMI_FAILURE) {
      log_error("vmi_events_listen failed.");
    }
  }
  // Process any remaining events.
  log_info("Event loop thread has finished processing events, exiting.");
  log_info("Signaling JSON serialization thread to stop.");
  g_atomic_int_set(&event_handler->stop_signal_json_serialization, 1);
  return NULL;
}

static gpointer event_window(gpointer data) {
  if (!data) {
    log_error("event_window: received NULL data pointer.");
    return NULL;
  }

  event_handler_t* event_handler = (event_handler_t*)data;

  // microseconds
  g_usleep((gulong)event_handler->window_seconds * 1000000);

  // Signal the event loop to stop
  g_atomic_int_set(&event_handler->stop_signal, 1);

  log_info("event_window: Signaled event loop to stop after %u seconds.",
           event_handler->window_seconds);

  return NULL;
}

void event_handler_start_event_window(event_handler_t* event_handler) {
  if (!event_handler) {
    log_error("event_handler_start_event_window: NULL handler.");
    return;
  }

  g_atomic_int_set(&event_handler->stop_signal, 0);

  // Launch the timer thread
  event_handler->signal_event_thread =
      g_thread_new("event_window", event_window, event_handler);
  if (!event_handler->signal_event_thread) {
    log_error("event_handler_start_event_window: Failed to create thread.");
  } else {
    log_info("Started event window thread to run for %u seconds.",
             event_handler->window_seconds);
  }
}

static gpointer json_serialization(gpointer data) {
  if (!data) {
    log_error("json_serialization: received NULL data pointer.");
    return NULL;
  }

  event_handler_t* event_handler = (event_handler_t*)data;
  if (!event_handler || !event_handler->serializer) {
    log_error("json_serialization: invalid event_handler or serializer.");
    return NULL;
  }

  json_serializer_t* serializer = event_handler->serializer;
  uint64_t last_flush = g_get_monotonic_time() / 1000;

  while (!g_atomic_int_get(&event_handler->stop_signal_json_serialization)) {
    int result = json_serializer_process_one(serializer);

    // Poll for 1ms
    if (result == 0) {
      g_usleep(1000);
    }

    uint64_t current_time = g_get_monotonic_time() / 1000;
    if (current_time - last_flush > serializer->flush_interval_ms) {
      last_flush = current_time;
    }
  }

  log_info("JSON serialization stopping, processing remaining responses.");

  int remaining = json_serializer_drain_queue(serializer);

  log_info("JSON serialization finished, processed %d remaining responses.",
           remaining);

  uint64_t queued, written, errors;
  json_serializer_get_stats(serializer, &queued, &written, &errors);
  log_info("Final JSON stats: queued: %lu, written: %lu, errors: %lu.", queued,
           written, errors);

  return NULL;
}

void event_handler_start_json_serialization(event_handler_t* event_handler) {
  if (!event_handler) {
    log_error("event_handler_start_json_serialization: NULL handler.");
    return;
  }

  // Launch the timer thread, it will singal both event loop and json serialization(?).
  event_handler->json_serialization_thread =
      g_thread_new("json_serilaziation", json_serialization, event_handler);
  if (!event_handler->json_serialization_thread) {
    log_error(
        "event_handler_start_json_serialization: Failed to create thread.");
  } else {
    log_info("Started json serialization thread.");
  }
}

void sample_state_tasks(event_handler_t* event_handler) {
  if (!event_handler) {
    log_error("The provided event_handler is NULL.");
    return;
  }

  // Check if the time since the last state sampling exceeds the configured interval.
  uint64_t current_time_ms = g_get_monotonic_time() / 1000;
  if (current_time_ms - event_handler->latest_state_sampling_ms <
      (uint64_t)event_handler->state_sampling_seconds * 1000) {
    log_warn(
        "State sampling skipped, "
        "not enough time has passed since the last sampling: "
        "%" PRIu64 " ms",
        current_time_ms - event_handler->latest_state_sampling_ms);
    return;
  }

  // Observation: The state sampling does not seem to hinder performance.
  // TODO: Profile/time to check.
  for (int i = 0; i < STATE_TASK_ID_MAX; ++i) {
    state_task_t* task = event_handler->state_tasks[i];
    if (task && task->functor) {
      log_info("Sampling state task: %s.", state_task_id_to_str(task->id));
      task->functor(event_handler->vmi, event_handler);
    }
  }

  event_handler->latest_state_sampling_ms = current_time_ms;
}

/**
 * @brief Create a interrupt task context object for the given task ID
 *
 * @param task_id The interrupt task ID.
 * @param symbol_name The symbol name associated with the task.
 * @return void*  The allocated context object, or NULL on error.
 */
static void* create_interrupt_task_context(interrupt_task_id_t task_id,
                                           const char* symbol_name) {
  switch (task_id) {
    case INTERRUPT_KPROBE: {
      kprobe_ctx_t* ctx = g_malloc0(sizeof(kprobe_ctx_t));
      if (ctx) {
        ctx->symname = g_strdup(symbol_name);
        ctx->kaddr = 0;
        ctx->orig = 0;
      }
      return ctx;
    }
    case INTERRUPT_EBPF_TRACEPOINT: {
      ebpf_tracepoint_ctx_t* ctx = g_malloc0(sizeof(ebpf_tracepoint_ctx_t));
      if (ctx) {
        ctx->symname = g_strdup(symbol_name);
        ctx->kaddr = 0;
        ctx->orig = 0;
      }
      return ctx;
    }
    case INTERRUPT_IO_URING_RING_WRITE: {
      io_uring_bp_ctx_t* ctx = g_malloc0(sizeof(io_uring_bp_ctx_t));
      if (ctx) {
        ctx->symname = symbol_name;
        ctx->kaddr = 0;
        ctx->orig = 0;
      }
      return ctx;
    }
    case INTERRUPT_NETWORK_MONITOR: {
      // Use the same context structure as netfilter for network monitoring
      nf_bp_ctx_t* ctx = g_malloc0(sizeof(nf_bp_ctx_t));
      if (ctx) {
        ctx->symname = symbol_name;
        ctx->kaddr = 0;
        ctx->orig = 0;
      }
      return ctx;
    }
    default:
      log_error("Unknown interrupt task type: %d.", task_id);
      return NULL;
  }
}

/**
 * @brief Map interrupt task ID to breakpoint type for dispatch
 *
 * @param task_id The interrupt task ID from configuration
 * @return breakpoint_type_t The corresponding breakpoint type, or BP_TYPE_MAX on error
 */
breakpoint_type_t interrupt_task_to_breakpoint_type(
    interrupt_task_id_t task_id) {
  switch (task_id) {
    case INTERRUPT_KPROBE:
      return BP_TYPE_KPROBE;
    case INTERRUPT_EBPF_TRACEPOINT:
      return BP_TYPE_EBPF_TRACEPOINT;
    case INTERRUPT_IO_URING_RING_WRITE:
      return BP_TYPE_IO_URING;
    case INTERRUPT_NETWORK_MONITOR:
      return BP_TYPE_NETWORK_MONITOR;
    default:
      log_error("Invalid interrupt task ID: %d.", task_id);
      return BP_TYPE_MAX;
  }
}

/**
 * @brief Register breakpoints for comprehensive network monitoring.
 *
 * @param event_handler The event handler instance.
 * @return int The number of successfully registered breakpoints.
 */
static int register_network_breakpoints(event_handler_t* event_handler) {
  static const char* network_symbols[] = {
      // // TCP connection management
      "tcp_connect", "tcp_accept", "tcp_close", "tcp_shutdown",
      // // UDP socket operations
      "udp_bind", "udp_connect", "udp_disconnect",
      // // Network interface operations
      "dev_open", "dev_close",
      // Socket binding and listening
      // "inet_bind", "inet_listen", "inet_accept",
      // Network filtering and hooks
      "nf_register_net_hook", "nf_unregister_net_hook", NULL};

  int registered = 0;
  breakpoint_type_t bp_type = BP_TYPE_NETWORK_MONITOR;

  for (int i = 0; network_symbols[i] != NULL; i++) {
    void* ctx = create_interrupt_task_context(INTERRUPT_NETWORK_MONITOR,
                                              network_symbols[i]);
    if (!ctx) {
      log_warn("Failed to create context for network symbol: %s.",
               network_symbols[i]);
      continue;
    }

    if (interrupt_context_add_breakpoint(event_handler->interrupt_context,
                                         event_handler->vmi, network_symbols[i],
                                         bp_type, ctx) == 0) {
      registered++;
      log_info("Registered network breakpoint: %s.", network_symbols[i]);
    } else {
      log_debug("Network symbol not found: %s.", network_symbols[i]);
      g_free(ctx);
    }
  }

  return registered;
}

/**
 * @brief Register breakpoints for common eBPF-related kernel functions.
 *
 * @param event_handler The event handler instance.
 * @return int The number of successfully registered breakpoints.
 */
static int register_kprobe_breakpoints(event_handler_t* event_handler) {
  static const char* kprobe_symbols[] = {
      "register_kprobe", "register_kretprobe", "register_uprobe", NULL};

  int registered = 0;
  breakpoint_type_t bp_type =
      interrupt_task_to_breakpoint_type(INTERRUPT_KPROBE);

  for (int i = 0; kprobe_symbols[i] != NULL; i++) {
    void* ctx =
        create_interrupt_task_context(INTERRUPT_KPROBE, kprobe_symbols[i]);
    if (!ctx) {
      log_warn("Failed to create context for kprobe symbol: %s.",
               kprobe_symbols[i]);
      continue;
    }

    if (interrupt_context_add_breakpoint(event_handler->interrupt_context,
                                         event_handler->vmi, kprobe_symbols[i],
                                         bp_type, ctx) == 0) {
      registered++;
      log_info("Registered kprobe breakpoint: %s.", kprobe_symbols[i]);
    } else {
      log_debug("Kprobe symbol not found: %s.", kprobe_symbols[i]);
      g_free(ctx);
    }
  }

  return registered;
}

static int register_ebpf_tracepoint_breakpoints(
    event_handler_t* event_handler) {
  static const char* ebpf_symbols[] = {"bpf_prog_attach",
                                       "bpf_raw_tracepoint_open",
                                       "tracepoint_probe_register", NULL};

  int registered = 0;
  breakpoint_type_t bp_type =
      interrupt_task_to_breakpoint_type(INTERRUPT_EBPF_TRACEPOINT);

  for (int i = 0; ebpf_symbols[i] != NULL; i++) {
    void* ctx = create_interrupt_task_context(INTERRUPT_EBPF_TRACEPOINT,
                                              ebpf_symbols[i]);
    if (!ctx) {
      log_warn("Failed to create context for eBPF symbol: %s.",
               ebpf_symbols[i]);
      continue;
    }

    if (interrupt_context_add_breakpoint(event_handler->interrupt_context,
                                         event_handler->vmi, ebpf_symbols[i],
                                         bp_type, ctx) == 0) {
      registered++;
      log_info("Registered eBPF tracepoint breakpoint: %s.", ebpf_symbols[i]);
    } else {
      log_debug("eBPF symbol not found: %s.", ebpf_symbols[i]);
      g_free(ctx);
    }
  }

  return registered;
}

/**
 * @brief Register a single breakpoint for the given interrupt task ID and symbol name.
 *
 * @param event_handler The event handler instance.
 * @param task_id The interrupt task ID.
 * @param symbol_name The symbol name to set the breakpoint on.
 * @return int 0 on success else -1 on failure.
 */
static int register_single_breakpoint(event_handler_t* event_handler,
                                      interrupt_task_id_t task_id,
                                      const char* symbol_name) {
  breakpoint_type_t bp_type = interrupt_task_to_breakpoint_type(task_id);
  if (bp_type < 0 || bp_type >= BP_TYPE_MAX) {
    log_error("Invalid breakpoint type for task ID: %d.", task_id);
    return -1;
  }

  void* ctx = create_interrupt_task_context(task_id, symbol_name);
  if (!ctx) {
    log_error("Failed to create context for interrupt task: %d.", task_id);
    return -1;
  }

  if (interrupt_context_add_breakpoint(event_handler->interrupt_context,
                                       event_handler->vmi, symbol_name, bp_type,
                                       ctx) != 0) {
    log_warn("Failed to register breakpoint for %s.", symbol_name);
    g_free(ctx);
    return -1;
  }

  log_info("Registered breakpoint: %s.", symbol_name);
  return 0;
}

int event_handler_register_interrupt_task(event_handler_t* event_handler,
                                          interrupt_task_id_t task_id) {
  // Preconditions
  if (!event_handler) {
    log_error("Invalid event handler.");
    return -1;
  }

  if (!event_handler->interrupt_context) {
    log_error("Interrupt context not initialized.");
    return -1;
  }

  if (task_id < 0 || task_id >= INTERRUPT_TASK_ID_MAX) {
    log_error("Invalid interrupt task ID: %d.", task_id);
    return -1;
  }

  if (event_handler->interrupt_tasks[task_id]) {
    log_warn("Interrupt task %s already registered.",
             interrupt_task_id_to_str(task_id));
    return 0;
  }

  int result = -1;
  switch (task_id) {
    case INTERRUPT_KPROBE:
      result = register_kprobe_breakpoints(event_handler);
      if (result > 0) {
        log_info("Registered %d kprobe breakpoints.", result);
        result = 0;  // Convert count to success/failure
      }
      break;
    case INTERRUPT_EBPF_TRACEPOINT:
      result = register_ebpf_tracepoint_breakpoints(event_handler);
      if (result > 0) {
        log_info("Registered %d eBPF tracepoint breakpoints.", result);
        result = 0;  // Convert count to success/failure
      }
      break;
    case INTERRUPT_IO_URING_RING_WRITE:
      result = register_single_breakpoint(event_handler, task_id,
                                          "__x64_sys_io_uring_enter");
      break;
    case INTERRUPT_NETWORK_MONITOR:
      result = register_network_breakpoints(event_handler);
      if (result > 0) {
        log_info("Registered %d network monitoring breakpoints.", result);
        result = 0;  // Convert count to success/failure
      }
      break;
    default:
      log_error("Unknown interrupt task ID: %d.", task_id);
      return -1;
  }

  if (result == 0) {
    event_handler->interrupt_tasks[task_id] = true;
    log_info("Successfully registered interrupt task: %s.",
             interrupt_task_id_to_str(task_id));
    return 0;
  }
  log_warn("Failed to register interrupt task: %s.",
           interrupt_task_id_to_str(task_id));
  return -1;
}

int event_handler_register_global_interrupt(event_handler_t* event_handler) {
  if (!event_handler || !event_handler->interrupt_context) {
    return -1;
  }

  if (event_handler->interrupt_context->count == 0) {
    log_info("No interrupt breakpoints registered.");
    return 0;
  }

  // Create and register the global INT3 event directly with VMI. In Xen, you can
  // only have one interrupt (INT3) event registered at a time.
  vmi_event_t* global_int3_event = g_malloc0(sizeof(vmi_event_t));
  if (!global_int3_event) {
    log_error("Failed to allocate global INT3 event.");
    return -1;
  }

  // TODO: Replace with SETUP from LibVMI.
  global_int3_event->version = VMI_EVENTS_VERSION;
  global_int3_event->type = VMI_EVENT_INTERRUPT;
  global_int3_event->interrupt_event.intr = INT3;
  global_int3_event->interrupt_event.reinject = -1;
  global_int3_event->callback = interrupt_context_global_callback;
  global_int3_event->data = event_handler->interrupt_context;

  if (vmi_register_event(event_handler->vmi, global_int3_event) !=
      VMI_SUCCESS) {
    log_error("Failed to register global INT3 event.");
    g_free(global_int3_event);
    return -1;
  }

  log_info("Registered global INT3 handler for %zu breakpoints.",
           event_handler->interrupt_context->count);

  // Save its reference for book-keeping purposes.
  event_handler->global_interrupt_event = global_int3_event;
  return 0;
}

bool event_handler_is_interrupt_task_registered(event_handler_t* event_handler,
                                                interrupt_task_id_t task_id) {
  if (!event_handler || task_id < 0 || task_id >= INTERRUPT_TASK_ID_MAX) {
    log_error("Invalid event handler or interrupt task ID.");
    return false;
  }

  return event_handler->interrupt_tasks[task_id];
}

int event_handler_unregister_interrupt_task(event_handler_t* event_handler,
                                            interrupt_task_id_t task_id) {
  // Preconditions
  if (!event_handler || !event_handler->interrupt_context) {
    log_error("Invalid event handler or interrupt context.");
    return -1;
  }

  if (task_id < 0 || task_id >= INTERRUPT_TASK_ID_MAX) {
    log_error("Invalid interrupt task ID: %d.", task_id);
    return -1;
  }

  if (!event_handler->interrupt_tasks[task_id]) {
    log_debug("Interrupt task %s not registered.",
              interrupt_task_id_to_str(task_id));
    return 0;
  }

  breakpoint_type_t bp_type = interrupt_task_to_breakpoint_type(task_id);
  if (bp_type == BP_TYPE_MAX) {
    return -1;
  }

  // Iterate through breakpoints and remove those matching the type.
  for (size_t i = 0; i < event_handler->interrupt_context->count; i++) {
    breakpoint_entry_t* breakpoint =
        &event_handler->interrupt_context->breakpoints[i];
    if (breakpoint->active && breakpoint->type == bp_type) {
      interrupt_context_remove_breakpoint(event_handler->interrupt_context,
                                          event_handler->vmi,
                                          breakpoint->kaddr);
    }
  }

  event_handler->interrupt_tasks[task_id] = false;
  log_info("Unregistered interrupt task: %s.",
           interrupt_task_id_to_str(task_id));

  return 0;
}