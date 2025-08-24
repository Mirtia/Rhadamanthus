#ifndef IO_URING_RING_WRITE_H
#define IO_URING_RING_WRITE_H
#include <libvmi/events.h>

/**
 * @brief Callback function for handling io_uring ring write events.
 * 
 * @param vmi The VMI instance.
 * @param event The event that triggered the callback.
 * @return event_response_t VMI_EVENT_RESPONSE_NONE (general monitoring).
 */

event_response_t event_io_uring_ring_write_callback(vmi_instance_t vmi,
                                                   vmi_event_t* event);

#endif  // IO_URING_RING_WRITE_H
