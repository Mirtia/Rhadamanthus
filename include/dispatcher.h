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
#define STATE_TASK_TIMEOUT \
  1000  // Timeout in milliseconds for busy waiting in state tasks.
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
typedef struct callback_event_item_t callback_event_item_t;

struct dispatcher {
  vmi_instance_t vmi;  ///< The LibVMI instance used by the dispatcher.
  GMutex vm_mutex;     ///< Mutex to handle callbacks and VMI pauses.

  state_task_t* state_tasks[STATE_TASK_ID_MAX];  ///< Array of state tasks
                                                 ///< indexed by their IDs.
  event_task_t* event_tasks[EVENT_TASK_ID_MAX];  ///< Array of event tasks
                                                 ///< indexed by their IDs.

  GThread* state_thread;  ///< Thread running periodic state tasks.
  GThread* event_thread;  ///< Thread running the LibVMI event loop.

  bool vm_paused;  ///< Flag indicating if the VM is currently paused.

  GThread* event_worker_thread;  ///< Thread processing events from the queue.
  GAsyncQueue*
      event_queue;  ///< Queue for events to be processed by the event worker thread.

  uint32_t
      window_ms;  ///< The time window in milliseconds for event processing.
  uint32_t
      state_sampling_ms;  ///< The frequency in milliseconds for state tasks sampling.
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
  event_response_t (*callback)(
      vmi_instance_t vmi,
      vmi_event_t* event);  ///< Keep - the callback function to execute when
                            ///< the event is triggered (conform to LibVMI).
  int64_t event_count;  ///< The number of times the event has been triggered.
};

/**
 * @brief It holds a copy of the VMI event and the task that triggered a callback.
 * Used for queueing events for processing in the event worker thread.
 */
struct callback_event_item_t {
  dispatcher_t* dispatcher;  ///< Needed to access mutex and VMI instance.
  event_task_t* task;        ///< The event task that triggered the callback.
  vmi_event_t event;         ///< Copy of the event data.
};

/**
 * @brief A state task is a periodic task that runs in its own GThread and
 * triggered by the dispatcher.
 */
struct state_task {
  state_task_id_t id;          ///< The ID of the state task.
  uint64_t last_invoked_time;  ///< The last time the task was invoked (in
                               ///< miliseconds since epoch).
  void* context;               ///< The context to pass to the task callback.
  uint32_t (*callback)(
      vmi_instance_t vmi,
      void* context);  ///< The callback function to execute when
                       ///< the task is triggered.
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
 * @brief Creating and initializing the dispatcher is responsible for managing
 * state and event tasks.
 *
 * @param vmi The LibVMI instance to use for the dispatcher.
 * @param window_ms The time window in milliseconds for event processing.
 * @param state_sample_interval_ms The frequency in milliseconds for state tasks
 * @return dispatcher_t* The created dispatcher instance.
 */
dispatcher_t* dispatcher_initialize(vmi_instance_t vmi, uint32_t window_ms,
                                    uint32_t state_sample_interval_ms);

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
 * @param context The context to pass to the task callback.
 * @param callback The callback function to execute when the task is triggered.
 */
void dispatcher_register_state_task(dispatcher_t* dispatcher,
                                    state_task_id_t task_id, void* context,
                                    uint32_t (*callback)(vmi_instance_t,
                                                         void*));

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
void dispatcher_register_event_task(dispatcher_t* dispatcher,
                                    event_task_id_t task_id, vmi_event_t filter,
                                    unsigned int (*callback)(vmi_instance_t,
                                                             vmi_event_t*));

/**
 * @brief The dispatcher starts a thread that runs periodic state tasks.
 * 
 * @param dispatcher The dispatcher instance.
 */
void dispatcher_start_state_loop(dispatcher_t* dispatcher);

/**
 * @brief The dispatcher starts a thread that runs the LibVMI event loop which waits for events.
 * 
 * @param dispatcher The dispatcher instance.
 */
void dispatcher_start_event_loop(dispatcher_t* dispatcher);

/**
 * @brief The dispatcher starts a thread that processes events from the queue.
 * 
 * @param dispatcher The dispatcher instance.
 */
void dispatcher_start_event_worker(dispatcher_t* dispatcher);

/**
 * @brief The gthread function that runs the event loop and processes events.
 * 
 * @param data The data passed to the ghtread function, in this context, the dispatcher instance.
 * @return gpointer The result of the thread execution, typically NULL.
 */
static gpointer event_loop_thread(gpointer data);

/**
 * @brief The gthread function that runs the periodic state tasks.
 * 
 * @param data The data passed to the ghtread function, in this context, the dispatcher instance.
 * @return gpointer The result of the thread execution, typically NULL.
 */
static gpointer state_loop_thread(gpointer data);

/**
 * @brief The gthread function that processes events from the queue.
 *
 * @param data The data passed to the ghtread function, in this context, the dispatcher instance.
 * @return gpointer The result of the thread execution, typically NULL.
 */
static gpointer event_worker_thread(gpointer data);

#endif  // DISPATCHER_H