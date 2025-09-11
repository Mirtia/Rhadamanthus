/**
 * @file utils.h
 * @brief Utility functions for error handling, logging, and kernel memory operations.
 * @version 0.0
 * @date 2025-09-11
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef UTILS_H
#define UTILS_H
#include <libvmi/events.h>
#include <libvmi/libvmi.h>
#include "event_handler.h"

/**
 * @brief Log an error message and queue an event response.
 * 
 * @param event_name The name of the event.
 * @param event_type The type of the event.
 * @param error_code The error code.
 * @param message The message to log.
 * @return event_response_t The event response indicating failure (e.g. VMI_EVENT_INVALID).
 */
event_response_t log_error_and_queue_response_event(const char* event_name,
                                                    event_task_id_t event_type,
                                                    int error_code,
                                                    const char* message);

/**
 * @brief Log an error message and queue a state task response.
 * 
 * @param task_name The name of the task.
 * @param task_type The type of the task.
 * @param error_code The error code.
 * @param message The message to log.
 * @return int The status code indicating failure (e.g. VMI_FAILURE).
 */
int log_error_and_queue_response_task(const char* task_name,
                                      state_task_id_t task_type, int error_code,
                                      const char* message);

/**
 * @brief Log an error message and queue an interrupt task response.
 * 
 * @param interrupt_name The name of the interrupt task.
 * @param interrupt_type The type of the interrupt task.
 * @param error_code The error code.
 * @param message The message to log.
 * @return event_response_t VMI_EVENT_RESPONSE_NONE on success, VMI_EVENT_INVALID on failure
 */
event_response_t log_error_and_queue_response_interrupt(
    const char* interrupt_name, interrupt_task_id_t interrupt_type,
    int error_code, const char* message);
/**
 * @brief Log success and queue response event with data
 * 
 * @param event_name Name of the event for logging/queueing
 * @param event_type The event task ID type
 * @param data_ptr Pointer to the data to include in response
 * @param data_free_func Function to free the data if response creation fails (can be NULL)
 * @return event_response_t VMI_EVENT_RESPONSE_NONE on success, VMI_EVENT_INVALID on failure
 */
event_response_t log_success_and_queue_response_event(
    const char* event_name, event_task_id_t event_type, void* data_ptr,
    void (*data_free_func)(void*));

/**
 * @brief Log success and queue response task with data
 * 
 * @param task_name Name of the task for logging/queueing
 * @param task_type The state task ID type
 * @param data_ptr Pointer to the data to include in response
 * @param data_free_func Function to free the data if response creation fails (can be NULL)
 * @return int VMI_SUCCESS on success, VMI_FAILURE on failure
 */
int log_success_and_queue_response_task(const char* task_name,
                                        state_task_id_t task_type,
                                        void* data_ptr,
                                        void (*data_free_func)(void*));

/**
 * @brief Log success and queue response interrupt with data
 * 
 * @param interrupt_name Name of the interrupt task for logging/queueing
 * @param interrupt_type The interrupt task ID type
 * @param data_ptr Nointer to the data to include in response
 * @param data_free_func Function to free the data if response creation fails (can be NULL)
 * @return event_response_t VMI_EVENT_RESPONSE_NONE on success, VMI_EVENT_INVALID on failure
 */
event_response_t log_success_and_queue_response_interrupt(
    const char* interrupt_name, interrupt_task_id_t interrupt_type,
    void* data_ptr, void (*data_free_func)(void*));

/**
 * @brief Get the kernel .text section start and end address.
 * 
 * @param vmi The VMI instance.
 * @param start_addr The output start address of the kernel text section.
 * @param end_addr The output end address of the kernel text section.
 * @return uint32_t VMI_SUCCESS on success, VMI_FAILURE on failure
 */
uint32_t get_kernel_text_section_range(vmi_instance_t vmi, addr_t* start_addr,
                                       addr_t* end_addr);

/**
 * @brief Check if an address lies within the kernel .text section bounds.
 *
 * @param vmi The VMI instance.
 * @param addr The address to check if in bounds.
 * @return true if the address is within bounds, false otherwise.
 */
bool is_in_kernel_text(vmi_instance_t vmi, addr_t addr);

/**
 * @brief Log the state of a vCPU.
 * 
 * @param vmi The VMI instance. 
 * @param vcpu_id The vCPU ID.
 * @param kaddr The kernel address of the vCPU structure.
 * @param context The context associated with the event.
 */
void log_vcpu_state(vmi_instance_t vmi, uint32_t vcpu_id, addr_t kaddr,
                    const char* context);

/**
 * @brief Add a uint64_t value as a hexadecimal string to a cJSON object.
 * 
 * @param parent The parent cJSON object to which the new item will be added.
 * @param key The key for the new item.
 * @param val The uint64_t value to add, which will be converted to a hex string.
 */
void cjson_add_hex_u64(cJSON* parent, const char* key, uint64_t val);

/**
 * @brief Add an addr_t value as a hexadecimal string to a cJSON object.
 * 
 * @param parent The parent cJSON object to which the new item will be added.
 * @param key The key for the new item.
 * @param val The addr_t value to add, which will be converted to a hex string.
 */
void cjson_add_hex_addr(cJSON* parent, const char* key, addr_t val);

/**
 * @brief Add a boolean value to a cJSON object.
 *
 * @param parent Parent cJSON object.
 * @param key Key to use for the new field.
 * @param value Boolean value to add.
 */
void cjson_add_bool(cJSON* parent, const char* key, bool value);

/**
 * @brief Add a uint32_t value as a hexadecimal string to a cJSON object.
 * 
 * @param parent The parent cJSON object to which the new item will be added.
 * @param key The key for the new item.
 * @param val The uint32_t value to add, which will be converted to a hex string.
 */
void cjson_add_hex_u32(cJSON* parent, const char* key, uint32_t val);

#endif