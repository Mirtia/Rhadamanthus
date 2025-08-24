#ifndef CODE_SECTION_MODIFY_H
#define CODE_SECTION_MODIFY_H

#include <libvmi/events.h>

/**
 * @brief Callback function for handling code section modifications.
 *
 * @param vmi The VMI instance.
 * @param event The event that triggered the callback.
 * @return event_response_t VMI_EVENT_RESPONSE_NONE (general monitoring).
 */
event_response_t event_code_section_modify_callback(vmi_instance_t vmi,
                                                    vmi_event_t* event);

#endif  // CODE_SECTION_MODIFY_H