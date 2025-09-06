#ifndef EVENT_HANDLER_H
#define EVENT_HANDLER_H

#include <glib-2.0/glib.h>
#include <libvmi/events.h>
#include <libvmi/libvmi.h>
#include "interrupt_context.h"

/**
 * @brief Constants
 */
#define EVENT_TASK_COUNT \
  100  // Maximum number of event tasks triggered during the time window. Print relevant warning when the threshold is surpassed.

/**
 * @brief  Task IDs for state tasks.
 */
enum state_task_id {
  STATE_KERNEL_MODULE_LIST = 0,  ///< List of kernel modules.
  STATE_FTRACE_HOOKS,            ///< List of ftrace hooks.
  STATE_NETWORK_TRACE,           ///< Network state information.
  STATE_SYSCALL_TABLE,           ///< Syscall table information.
  STATE_IDT_TABLE,            ///< IDT table state check (are there any hooks?).
  STATE_DIR_STRING_MATCHING,  ///< Check directories and files of interest.
  STATE_PROCESS_LIST,         ///< List of processes.
  STATE_MSR_REGISTERS,   ///< MSR register state check (are there any hooks?).
  STATE_EBPF_ARTIFACTS,  ///< eBPF programs and maps state check.
  STATE_IO_URING_ARTIFACTS,  ///< io_uring structures state check.,
  STATE_KALLSYMS_SYMBOLS,    ///< kallsyms symbols state check.
  STATE_TASK_ID_MAX          ///< Maximum number of state tasks.
};

/**
 * @brief Task IDs for event tasks.
 */
enum event_task_id {
  EVENT_FTRACE_HOOK = 0,          ///< ftrace hook detection
  EVENT_SYSCALL_TABLE_WRITE,      ///< syscall table write detection
  EVENT_IDT_WRITE,                ///< IDT hook detection
  EVENT_CR0_WRITE,                ///< write access to control register
  EVENT_PAGE_TABLE_MODIFICATION,  ///< page table or memory mapping change
  EVENT_MSR_WRITE,                ///< MSR register access detection
  EVENT_CODE_SECTION_MODIFY,      ///< kernel code integrity
  EVENT_KALLSYMS_TABLE_WRITE,     ///< kallsyms or symbol hijacking
  EVENT_TASK_ID_MAX               ///< Maximum number of event tasks.
};

/**
 * @brief Task IDs for interrupt tasks.
 */
enum interrupt_task_id {
  INTERRUPT_EBPF_PROBE = 0,        ///< eBPF/kprobe function monitoring.
  INTERRUPT_IO_URING_RING_WRITE,   ///< io_uring ring buffer write monitoring.
  INTERRUPT_NETFILTER_HOOK_WRITE,  ///< Netfilter hook registration monitoring.
  INTERRUPT_TASK_ID_MAX            ///< Maximum number of interrupt tasks.
};

// Type definitions for the event_handler and task structures
typedef struct event_handler event_handler_t;
typedef struct event_task event_task_t;
typedef struct state_task state_task_t;
typedef enum state_task_id state_task_id_t;
typedef enum event_task_id event_task_id_t;
typedef enum interrupt_task_id interrupt_task_id_t;
typedef struct callback_event_item_t callback_event_item_t;

struct event_handler {
  vmi_instance_t vmi;  ///< The LibVMI instance used by the event_handler.
  state_task_t* state_tasks[STATE_TASK_ID_MAX];  ///< Array of state tasks
                                                 ///< indexed by their IDs.
  event_task_t* event_tasks[EVENT_TASK_ID_MAX];  ///< Array of event tasks
  ///< indexed by their IDs.
  bool interrupt_tasks
      [INTERRUPT_TASK_ID_MAX];  ///< Array of interrupt tasks (if they are enabled or not) indexed by their IDs.
  interrupt_context_t* interrupt_context;  // The shared interrupt context.
  vmi_event_t* global_interrupt_event;     ///< The LibVMI event for interrupts.
  uint32_t window_ms;  ///< The time window in milliseconds for monitoring.
  uint32_t
      state_sampling_ms;  ///< The frequency in milliseconds for state tasks sampling.
  uint64_t
      latest_state_sampling_ms;  ///< The latest time in milliseconds since epoch when the state tasks were sampled. Used to limit the frequency of state tasks execution.
  GThread* event_thread;         ///< The thread running the LibVMI event loop.
  GThread*
      signal_event_thread;  ///< The thread that signals the event loop to stop processing events after window ms.
  GThread*
      json_serialization_thread;  ///< The thread that handles JSON serialization of events. We do not want blocking I/O operations in the event callbacks.
  volatile sig_atomic_t
      stop_signal;  ///< Signal to stop the event loop after the time window.
  // TODO: Add thread that does post-processing / serialization / storage of the events.
  volatile bool is_paused;  ///< Flag to indicate if vm is paused.
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
  GPtrArray* events;    ///< The LibVMI event array.
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
 * @brief Convert an interrupt task ID to a string representation.
 *
 * @param task_id The interrupt task ID to convert.
 * @return const char* The string representation of the task ID else NULL.
 */
const char* interrupt_task_id_to_str(interrupt_task_id_t task_id);

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
 * @brief Parse a string into an interrupt_task_id_t.
 * @param str The input string.
 * @return Corresponding enum value, or -1 on failure.
 */
int interrupt_task_id_from_str(const char* str);

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
 * @param events The LibVMI events to monitor.
 * @param callback The callback function to execute when the event is triggered.
 */
void event_handler_register_event_task(event_handler_t* event_handler,
                                       event_task_id_t task_id,
                                       GPtrArray* events);

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
 * @brief Register an interrupt-driven task with the event_handler.
 * 
 * @param event_handler The event_handler instance.
 * @param task_id The ID of the interrupt task to register.
 * @return int 0 on success, -1 on failure.
 */
int event_handler_register_interrupt_task(event_handler_t* event_handler,
                                          interrupt_task_id_t task_id);

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
 * @brief The event_handler starts a thread that has a thread sleeping 
 * for window_ms till it sends a singal to the event processing loop.
 * 
 * @param event_handler The event_handler instance.
 */
void event_handler_start_event_window(event_handler_t* event_handler);

/**
 * @brief The gthread function that runs the event window timer and sends a signal.
 * 
 * @param data The data passed to the ghtread function, in this context, the event_handler instance.
 * @return gpointer The result of the thread execution, typically NULL.
 */
static gpointer event_window(gpointer data);

/**
 * @brief The event_handler starts a thread that handles JSON serialization of events.
 * 
 * @param event_handler The event_handler instance.
 */
void event_handler_start_json_serilaziation(event_handler_t* event_handler);

/**
 * @brief The function that calls all state functors.
 * 
 * @param event_handler The event_handler instance.
 */
void sample_state_tasks(event_handler_t* event_handler);

/**
 * @brief Register a global interrupt event to handle all interrupt-driven tasks.
 * 
 * @details Store the event to the handler for book-keeping and later cleanup. 
 *
 * @param event_handler The event_handler instance.
 * @return int 0 on success, -1 on failure.
 */
int event_handler_register_global_interrupt(event_handler_t* event_handler);

/**
 * @brief Convert interrupt task ID to breakpoint type.
 * 
 * This function should be declared elsewhere (event_handler.h) but is used
 * in the implementation files, so including the declaration here for reference.
 * 
 * @param task_id Interrupt task ID.
 * @return breakpoint_type_t Corresponding breakpoint type.
 */
breakpoint_type_t interrupt_task_to_breakpoint_type(
    interrupt_task_id_t task_id);

#endif  // EVENT_HANDLER_H