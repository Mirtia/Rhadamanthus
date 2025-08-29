#ifndef IO_URING_RING_WRITE_H
#define IO_URING_RING_WRITE_H
#include <libvmi/events.h>

/**
 * @brief Callback to detect io_uring events.
 * 
 * @param vmi The vmi instance.
 * @param event The event.
 * @return event_response_t The event response.
 */
event_response_t event_io_uring_ring_write_callback(vmi_instance_t vmi,
                                                    vmi_event_t* event);

/**
 * @brief Entry BP handler (called on #BP at the function entry) __x64_sys_io_uring_enter
 * 
 * @param vmi The VMI instance.
 * @param event The singlestep event to identify origin of the callback.
 * @return event_response_t The event response.
 */
event_response_t event_io_uring_ring_write_ss_callback(vmi_instance_t vmi,
                                                       vmi_event_t* event);

#endif  // IO_URING_RING_WRITE_H
