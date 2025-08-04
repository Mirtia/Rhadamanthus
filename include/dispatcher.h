#ifndef DISPATCHER_H
#define DISPATCHER_H

#include <glib-2.0/glib.h>
#include <libvmi/events.h>
#include <libvmi/libvmi.h>

/**
 * @brief Constants
 */
#define EVENT_TASK_COUNT \
  100  // Maximum number of event tasks triggered during the time window.

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
  // TODO: What is this?
  STATE_PROCFS_ARTIFACTS,
  STATE_NETFILTER_HOOKS,
  STATE_KERNEL_THREADS,
  STATE_KPROBES_JPROBES_KRETPROBES,
  STATE_MSR_REGISTERS,
  STATE_KERNEL_CODE_INTEGRITY_CHECK,
  STATE_EBPF_ARTIFACTS,
  STATE_IO_URING_ARTIFACTS,
  STATE_CREDENTIALS,
  STATE_KALLSYMS_SYMBOLS,
  STATE_FIRMWARE_ACPI_HOOKS,
  // TODO: Add more state tasks as needed.
  STATE_TASK_ID_MAX
};

/**
 * @brief Task IDs for event tasks.
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

// Type definitions for the dispatcher and task structures
typedef struct dispatcher dispatcher_t;
typedef struct event_task event_task_t;
typedef struct state_task state_task_t;
typedef enum state_task_id state_task_id_t;
typedef enum event_task_id event_task_id_t;

struct dispatcher {
  vmi_instance_t vmi;  ///< The LibVMI instance used by the dispatcher.
  GMutex vm_mutex;     ///< Mutex to handle callbacks and VMI pauses.

  state_task_t* state_tasks[STATE_TASK_ID_MAX];  ///< Array of state tasks
                                                 ///< indexed by their IDs.
  event_task_t* event_tasks[EVENT_TASK_ID_MAX];  ///< Array of event tasks
                                                 ///< indexed by their IDs.

  GThread* state_thread;  ///< Thread running periodic state tasks.
  GThread* event_thread;  ///< Thread running the LibVMI event loop.
};

/**
 * @brief The event context is used to pass to the callback.
 */
struct event_ctx {
  dispatcher_t*
      dispatcher;  ///< The dispatcher instance that manages the event tasks.
  event_task_t* task;  ///<  The event task that is currently being processed.
};

/**
 * @brief An event task is a persistent LibVMI event registration.
 *
 * Each event task defines a callback that may be triggered multiple times
 * throughout execution whenever the registered condition is met (e.g. memory
 * write, CR register access, etc).
 */
struct event_task {
  event_task_id_t id;  ///< The ID of the event task.
  vmi_event_t filter;  ///< The LibVMI event filter that triggers the task.
  void* context;       ///< The context to pass to the task callback.
  void (*callback)(vmi_instance_t vmi, vmi_event_t* event,
                   void* context);  ///< The callback function to execute when
                                    ///< the event is triggered.
  int64_t event_count;  ///< The number of times the event has been triggered.
};

/**
 * @brief A state task is a periodic task that runs in its own GThread and
 * triggered by the dispatcher.
 */
struct state_task {
  state_task_id_t id;  ///< The ID of the state task.
  double interval_ms;  ///< The interval in miliseconds at which the task is
                       ///< repeated.
  double last_invoked_time;  ///< The last time the task was invoked (in
                             ///< miliseconds since epoch).
  void* context;             ///< The context to pass to the task callback.
  void (*callback)(vmi_instance_t vmi,
                   void* context);  ///< The callback function to execute when
                                    ///< the task is triggered.
};

/**
 * @brief Convert a state task ID to a string representation.
 *
 * @param task_id The state task ID to convert.
 * @return const char* The string representation of the task ID.
 */
const char* state_task_id_to_string(state_task_id_t task_id);

/**
 * @brief Convert a state task ID to a string representation.
 *
 * @param task_id The event task ID to convert.
 * @return const char* The string representation of the task ID.
 */
const char* event_task_id_to_string(event_task_id_t task_id);

/**
 * @brief Creating and initializing the dispatcher is responsible for managing
 * state and event tasks.
 *
 * @param vmi The LibVMI instance to use for the dispatcher.
 * @return dispatcher_t* The created dispatcher instance.
 */
dispatcher_t* dispatcher_initialize(vmi_instance_t vmi);

/**
 * @brief Cleaning up and freeing the resources used by the dispatcher.
 *
 * @param disp The dispatcher instance to free.
 */
void dispatcher_free(dispatcher_t* dispatcher);

/**
 * @brief Register a periodic state task with the dispatcher.
 *
 * @param dispatcher The dispatcher instance.
 * @param id The ID of the state task to register.
 * @param interval_s The interval in miliseconds at which the task should be
 * repeated.
 * @param context The context to pass to the task callback.
 * @param callback The callback function to execute when the task is triggered.
 */
void dispatcher_register_state_task(dispatcher_t* dispatcher,
                                    state_task_id_t task_id, double interval_ms,
                                    void* context,
                                    void (*callback)(vmi_instance_t, void*));

// Register an event-driven task (handled sequentially by LibVMI)
/**
 * @brief Register an event-driven task with the dispatcher.
 *
 * @param dispatcher The dispatcher instance.
 * @param id The ID of the event task to register.
 * @param filter The LibVMI event filter that triggers the task.
 * @param context The context to pass to the task callback.
 * @param callback The callback function to execute when the event is triggered.
 */
void dispatcher_register_event_task(
    dispatcher_t* dispatcher, event_task_id_t task_id, vmi_event_t filter,
    void* context, void (*callback)(vmi_instance_t, vmi_event_t*, void*));

#endif  // DISPATCHER_H