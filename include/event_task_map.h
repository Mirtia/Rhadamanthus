#ifndef EVENT_TASK_MAP_H
#define EVENT_TASK_MAP_H

#include <glib-2.0/glib.h>
#include <libvmi/libvmi.h>
#include "event_handler.h"

/**
 * @brief Register all available event tasks with the event handler
 * 
 * This function registers all event tasks defined in the event_task_map
 * with the provided event handler. It will attempt to create and register
 * each event, logging success or failure for each one.
 * 
 * @param event_handler Initialized event handler instance
 * @return Number of successfully registered event tasks, or -1 on error
 */
int register_all_event_tasks(event_handler_t* event_handler);

/**
 * @brief Register a specific event task by ID
 * 
 * This function registers a single event task identified by task_id
 * with the provided event handler.
 * 
 * @param event_handler Initialized event handler instance
 * @param task_id Event task ID to register
 * @return 1 on success, -1 on error
 */
int register_event_task_by_id(event_handler_t* event_handler,
                              event_task_id_t task_id);

/**
 * @brief List all available event tasks
 * 
 * This function logs information about all available event tasks,
 * including their IDs, names, and descriptions.
 */
void list_available_event_tasks(void);

#endif /* EVENT_TASK_MAP_H */