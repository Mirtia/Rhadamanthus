#ifndef IO_URING_RING_WRITE_H
#define IO_URING_RING_WRITE_H
#include <libvmi/events.h>

/**
 * @brief Context structure for io_uring enter syscall breakpoint handling.
 */
typedef struct io_uring_bp_ctx {
  addr_t kaddr;         ///< kernel VA of __x64_sys_io_uring_enter */
  uint8_t orig;         ///< original first byte (before 0xCC) */
  vmi_event_t ss_evt;   ///< one-shot SINGLESTEP event, registered from BP cb */
  const char* symname;  ///< for logs */
} io_uring_bp_ctx_t;

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
