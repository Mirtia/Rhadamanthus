/**
 * @file state_task_map.h
 * @brief Header file for mapping state task IDs to their corresponding function pointers.
 * @version 0.0
 * @date 2025-09-11
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef STATE_TASK_MAP_H
#define STATE_TASK_MAP_H
#include <libvmi/libvmi.h>
#include "event_handler.h"

uint32_t (*get_state_task_functor(state_task_id_t task_id))(vmi_instance_t,
                                                            void*);

#endif  // STATE_TASK_MAP_H