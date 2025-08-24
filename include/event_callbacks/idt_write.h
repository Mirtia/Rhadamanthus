#ifndef IDT_WRITE_H
#define IDT_WRITE_H

#include <libvmi/events.h>

/**
 * @brief Callback function for handling IDT write events.
 *
 * @param vmi The VMI instance.
 * @param event The event that triggered the callback.
 * @return event_response_t VMI_EVENT_RESPONSE_NONE (general monitoring).
 */
event_response_t event_idt_write_callback(vmi_instance_t vmi,
                                          vmi_event_t* event);
                                          #endif // IDT_WRITE_H