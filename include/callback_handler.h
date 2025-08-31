#ifndef CALLBACK_HANDLER_H
#define CALLBACK_HANDLER_H

#include "event_handler.h"

// typedef uint32_t (*state_task_callback_t)(vmi_instance_t, void*);
// typedef event_response_t (*event_task_callback_t)(vmi_instance_t, vmi_event_t*);

/**
 * @brief Get the callback function for a given state task ID.
 *
 * @param task_id The state task ID.
 * @return A function pointer to the callback, or NULL if not implemented.
 */
state_task_callback_t get_state_task_callback(state_task_id_t task_id);

/**
 * @brief Get the callback function for a given event task ID.
 *
 * @param task_id The event task ID.
 * @return A function pointer to the callback, or NULL if not implemented.
 */
event_task_callback_t get_event_task_callback(event_task_id_t task_id);

#endif  // CALLBACK_HANDLER_H
