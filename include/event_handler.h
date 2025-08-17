#ifndef EVENT_HANDLER_H
#define EVENT_HANDLER_H

#include <glib-2.0/glib.h>
#include <libvmi/events.h>
#include <libvmi/libvmi.h>

/**
 * @brief Constants
 */
#define EVENT_TASK_COUNT \
  100  // Maximum number of event tasks triggered during the time window. Print relevant warning when the threshold is surpassed.

/**
 * @brief  Task IDs for state tasks.
 */
enum state_task_id {
  STATE_KERNEL_MODULE_LIST,
  STATE_FTRACE_HOOKS,
  STATE_NETWORK_TRACE,
  STATE_SYSCALL_TABLE,
  STATE_IDT_TABLE,
  STATE_DIR_STRING_MATCHING,
  STATE_PROCESS_LIST,
  // TODO: What is this? Some fields may be redundant. Object to change.
  STATE_MSR_REGISTERS,
  STATE_KERNEL_CODE_INTEGRITY_CHECK,
  STATE_EBPF_ARTIFACTS,
  STATE_IO_URING_ARTIFACTS,
  STATE_KALLSYMS_SYMBOLS,
  STATE_FIRMWARE_ACPI_HOOKS,
  // TODO: Add more state tasks as needed.
  STATE_TASK_ID_MAX
};

/**
 * @brief Task IDs for event tasks.
 * TODO: Remove some of those.
 */
enum event_task_id {
  EVENT_FTRACE_PATCHING,          ///< ftrace hook detection
  EVENT_SYSCALL_TABLE_WRITE,      ///< syscall table write detection
  EVENT_IDT_ENTRY_MODIFICATION,   ///< IDT hook detection
  EVENT_CR0_WRITE,                ///< write access to control register
  EVENT_PAGE_TABLE_MODIFICATION,  ///< page table or memory mapping change
  EVENT_NETFILTER_HOOK_WRITE,     ///< function pointer hook detection
  EVENT_MSR_WRITE,                ///< MSR register access detection
  EVENT_CODE_SECTION_MODIFY,      ///< kernel code integrity
  EVENT_INTROSPECTION_INTEGRITY,  ///< self-monitoring trap
  EVENT_IO_URING_RING_WRITE,      ///< io_uring structure tampering
  EVENT_EBPF_MAP_UPDATE,          ///< eBPF map or program overwrite
  EVENT_KALLSYMS_TABLE_WRITE,     ///< kallsyms or symbol hijacking
  // TODO: Add more event tasks as needed.
  EVENT_TASK_ID_MAX
};

// Type definitions for the event_handler and task structures
typedef struct event_handler event_handler_t;
typedef struct event_task event_task_t;
typedef struct state_task state_task_t;
typedef enum state_task_id state_task_id_t;
typedef enum event_task_id event_task_id_t;
typedef struct callback_event_item_t callback_event_item_t;

struct event_handler {
  vmi_instance_t vmi;  ///< The LibVMI instance used by the event_handler.
  state_task_t* state_tasks[STATE_TASK_ID_MAX];  ///< Array of state tasks
                                                 ///< indexed by their IDs.
  event_task_t* event_tasks[EVENT_TASK_ID_MAX];  ///< Array of event tasks
                                                 ///< indexed by their IDs.

  uint32_t window_ms;  ///< The time window in milliseconds for monitoring.
  uint32_t
      state_sampling_ms;  ///< The frequency in milliseconds for state tasks sampling.
  uint64_t
      latest_state_sampling_ms;  ///< The latest time in milliseconds since epoch when the state tasks were sampled. Used to limit the frequency of state tasks execution.
  GThread* event_thread;         ///< The thread running the LibVMI event loop.
  // TODO: Add thread that does post-processing / serialization / storage of the events.
};

/**
 * @brief An event task is a persistent LibVMI event registration.
 *
 * Each event task defines a callback that may be triggered multiple times
 * throughout execution whenever the registered condition is met (e.g. memory
 * write, CR register access, etc).
 */
struct event_task {
  event_task_id_t
      id;  ///< The ID of the event task (1-1 mapping with Event IDs).
  vmi_event_t* event;   ///< The LibVMI event.
  int64_t event_count;  ///< The number of times the event has been triggered.
};

/**
 * @brief A state task acts as a state information extractor for the system every time
 * an LibVMI is triggered.
 */
struct state_task {
  state_task_id_t
      id;  ///< The ID of the state task (1- 1 mapping with State IDs).
  uint32_t (*functor)(
      vmi_instance_t vmi,
      void* context);  ///< The functor to run for the state task.
};

/**
 * @brief Convert a state task ID to a string representation.
 *
 * @param task_id The state task ID to convert.
 * @return const char* The string representation of the task ID else NULL.
 */
const char* state_task_id_to_str(state_task_id_t task_id);

/**
 * @brief Convert a state task ID to a string representation.
 *
 * @param task_id The event task ID to convert.
 * @return const char* The string representation of the task ID else NULL.
 */
const char* event_task_id_to_str(event_task_id_t task_id);

/**
 * @brief Parse a string into a state_task_id_t.
 * @param str The input string.
 * @return Corresponding enum value, or -1 on failure.
 */
int state_task_id_from_str(const char* str);

/**
 * @brief Parse a string into an event_task_id_t.
 * @param str The input string.
 * @return Corresponding enum value, or -1 on failure.
 */
int event_task_id_from_str(const char* str);

/**
 * @brief Creating and initializing the event_handler is responsible for managing
 * state and event tasks.
 *
 * @param vmi The LibVMI instance to use for the event_handler.
 * @param window_ms The time window in milliseconds for event processing.
 * @param state_sampling_ms The frequency in milliseconds for state tasks
 * @return event_handler_t* The created event_handler instance.
 */
event_handler_t* event_handler_initialize(vmi_instance_t vmi,
                                          uint32_t window_ms,
                                          uint32_t state_sampling_ms);

/**
 * @brief Cleaning up and freeing the resources used by the event_handler.
 *
 * @param event_handler The event_handler instance to free.
 */
void event_handler_free(event_handler_t* event_handler);

/**
 * @brief Register an event-driven task with the event_handler.
 *
 * @param event_handler The event_handler instance.
 * @param id The ID of the event task to register.
 * @param event The LibVMI event filter that triggers the task.
 * @param callback The callback function to execute when the event is triggered.
 */
void event_handler_register_event_task(
    event_handler_t* event_handler, event_task_id_t task_id, vmi_event_t* event,
    unsigned int (*callback)(vmi_instance_t, vmi_event_t*));

/**
 * @brief Register a state task with the event_handler.
 * 
 * @param event_handler The event_handler instance.
 * @param task_id The ID of the state task to register.
 * @param functor The function to execute when the state task is triggered.
 */
void event_handler_register_state_task(event_handler_t* event_handler,
                                       state_task_id_t task_id,
                                       uint32_t (*functor)(vmi_instance_t,
                                                           void*));

/**
 * @brief The event_handler starts a thread that runs the LibVMI event loop which waits for events.
 * 
 * @param event_handler The event_handler instance.
 */
void event_handler_start_event_loop(event_handler_t* event_handler);

/**
 * @brief The gthread function that runs the event loop and processes events.
 * 
 * @param data The data passed to the ghtread function, in this context, the event_handler instance.
 * @return gpointer The result of the thread execution, typically NULL.
 */
static gpointer event_loop_thread(gpointer data);

/**
 * @brief The function that calls all state functors.
 * 
 * @param event_handler The event_handler instance.
 */
void sample_state_tasks(event_handler_t* event_handler);

#endif  // EVENT_HANDLER_H