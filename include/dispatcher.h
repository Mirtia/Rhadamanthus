#ifndef DISPATCHER_H
#define DISPATCHER_H

#include <glib-2.0/glib.h>
#include <libvmi/events.h>
#include <libvmi/libvmi.h>

/**
 * @brief Constants
 */
#define EVENT_TASK_COUNT                                                       \
  100 // Maximum number of event tasks triggered during the time window.

/**
 * @brief  Task IDs for state tasks.
 */
enum state_task_id {
  TASK_MODULE_LIST,
  // TODO: Add more state tasks as needed.
  TASK_STATE_ID_MAX
};

/**
 * @brief Task IDs for event tasks.
 */
enum event_task_id {
  EVENT_CR0_ACCESS,
  // TODO: Add more event tasks as needed.
  EVENT_STATE_ID_MAX
};

// Type definitions for the dispatcher and task structures
typedef struct dispatcher dispatcher_t;
typedef struct event_task event_task_t;
typedef struct state_task state_task_t;
typedef enum state_task_id state_task_id_t;
typedef enum event_task_id event_task_id_t;

struct dispatcher {
  vmi_instance_t vmi; ///< The LibVMI instance used by the dispatcher.
  GMutex vm_mutex;    ///< Mutex to handle callbacks and VMI pauses.

  state_task_t *state_tasks[TASK_STATE_ID_MAX];  ///< Array of state tasks
                                                 ///< indexed by their IDs.
  event_task_t *event_tasks[EVENT_STATE_ID_MAX]; ///< Array of event tasks
                                                 ///< indexed by their IDs.
};

/**
 * @brief The event context is used to pass to the callback.
 */
struct event_ctx {
  dispatcher_t
      *dispatcher;    ///< The dispatcher instance that manages the event tasks.
  event_task_t *task; ///<  The event task that is currently being processed.
};

/**
 * @brief An event task is a LibVMI event that is triggered by the dispatcher.
 * The dispatcher loops over all registered event tasks and process them
 * sequentially.
 */
struct event_task {
  event_task_id_t id; ///< The ID of the event task.
  vmi_event_t filter; ///< The LibVMI event filter that triggers the task.
  void *context;      ///< The context to pass to the task callback.
  void (*callback)(vmi_instance_t vmi, vmi_event_t *event,
                   void *context); ///< The callback function to execute when
                                   ///< the event is triggered.
};

/**
 * @brief A state task is a periodic task that runs in its own GThread and
 * triggered by the dispatcher.
 */
struct state_task {
  state_task_id_t id; ///< The ID of the state task.
  double interval_ms; ///< The interval in miliseconds at which the task is
                      ///< repeated.
  double last_invoked_time; ///< The last time the task was invoked (in
                            ///< miliseconds since epoch).
  void *context; ///< The context to pass to the task callback.
  void (*callback)(vmi_instance_t vmi,
                   void *context); ///< The callback function to execute when
                                   ///< the task is triggered.
};

/**
 * @brief Convert a state task ID to a string representation.
 *
 * @param id The state task ID to convert.
 * @return const char* The string representation of the task ID.
 */
const char *state_task_id_to_string(state_task_id id);

/**
 * @brief Convert a state task ID to a string representation.
 *
 * @param id The event task ID to convert.
 * @return const char* The string representation of the task ID.
 */
const char *event_task_id_to_string(event_task_id id);

/**
 * @brief Creating and initializing the dispatcher is responsible for managing
 * state and event tasks.
 *
 * @param vmi The LibVMI instance to use for the dispatcher.
 * @return dispatcher_t* The created dispatcher instance.
 */
dispatcher_t *dispatcher_initialize(vmi_instance_t vmi);

/**
 * @brief Cleaning up and freeing the resources used by the dispatcher.
 *
 * @param disp The dispatcher instance to free.
 */
void dispatcher_free(dispatcher_t *dispatcher);

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
void dispatcher_register_state_task(dispatcher_t *dispatcher, state_task_id_t id,
                                    double interval_ms, void *context,
                                    void (*callback)(vmi_instance_t, void *));

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
void dispatcher_register_event_task(dispatcher_t *dispatcher, event_task_id_t id,
                                    vmi_event_t filter, void *context,
                                    void (*callback)(vmi_instance_t,
                                                     vmi_event_t *, void *));

#endif // DISPATCHER_H