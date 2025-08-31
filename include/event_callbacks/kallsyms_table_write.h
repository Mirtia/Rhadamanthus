/**
 * @file kallsyms_table_write.h
 * @author Myrsini Gkolemi
 * @brief The file monitors kernel symbols modifications.
 * @version 0.0
 * @date 2025-08-24
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef KALLSYMS_TABLE_WRITE_H
#define KALLSYMS_TABLE_WRITE_H

#include <libvmi/events.h>
/**
 * @brief Callback function for handling kallsyms table write events.
 *
 * @param vmi The VMI instance.
 * @param event The event that triggered the callback.
 * @return event_response_t VMI_EVENT_RESPONSE_NONE (general monitoring).
 */
event_response_t event_kallsyms_write_callback(vmi_instance_t vmi,
                                                      vmi_event_t* event);

#endif  // KALLSYMS_TABLE_WRITE_H