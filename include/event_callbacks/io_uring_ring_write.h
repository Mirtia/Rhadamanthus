/**
 * @file io_uring_ring_write.h
 * @author Myrsini Gkolemi
 * @brief This file monitors io_uring io_uring_enter events.
 * @version 0.0
 * @date 2025-08-31
 * 
 * @copyright Copyright (c) 2025
 * 
 */
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
 * @details It is invoked when the execution hits an INT3 breakpoint
 * placed at the entry of the kernel's `io_uring_enter` handler.
 * Its responsibilities include:
 *  * Restoring the original instruction byte at the breakpoint site,
 *  * Logging the arguments to `io_uring_enter` (fd, to_submit, min_complete, flags, sig, sigsz),
 *  * Enabling single-step execution (by setting the trap flag, TF),
 *  * Rewinding RIP by 1 to re-execute the original first instruction,
 *  * Registering a one-shot SINGLESTEP event to re-arm the INT3 breakpoint
 *    and clear TF after single-stepping.
 *
 * @param vmi The VMI instance.
 * @param event The event that triggered the callback.
 * @return event_response_t VMI_EVENT_RESPONSE_NONE (general monitoring).
 */
event_response_t event_io_uring_ring_write_callback(vmi_instance_t vmi,
                                                    vmi_event_t* event);

#endif  // IO_URING_RING_WRITE_H
