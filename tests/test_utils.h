/**
 * @file test_utils.h
 * @brief This header file contains utility functions for generating and freeing data objects for testing. 
 * 
 */
#ifndef TEST_UTILS_H
#define TEST_UTILS_H
#include <libvmi/events.h>
#include <libvmi/libvmi.h>
#include "dispatcher.h"

/**
 * @brief 
 * 
 * @param vmi 
 * @param type 
 * @param pid 
 * @param tid 
 * @return vmi_event_t 
 */
vmi_event_t generate_event(vmi_instance_t vmi, vmi_event_type_t type,
                           vmi_pid_t pid, vmi_pid_t tid);

/**
 * @brief This function is a mock task event callback for testing purposes.
 * 
 * @param vmi The instance of the VMI library. [[unused]]
 * @param event The event that triggered this callback. [[unused]]
 */
void mock_task_callback_event_task(vmi_instance_t vmi, vmi_event_t* event);

/**
 * @brief This function is a mock task state callback for testing purposes.
 * 
 * @param vmi The instance of the VMI library. [[unused]]
 * @param event The event that triggered this callback. [[unused]]
 */
void mock_task_callback_state_task(vmi_instance_t vmi, vmi_event_t* event);

/**
 * @brief This function is responsible for registering the mock tasks at the dispatcher.
 * 
 * @param dispatcher The dispatcher instance where the mock tasks will be registered.
 */
void register_mock_tasks(dispatcher_t* dispatcher);

#endif  // TEST_UTILS_H