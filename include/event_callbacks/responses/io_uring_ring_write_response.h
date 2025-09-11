/**
 * @file io_uring_ring_write_response.h
 * @brief Response structure and functions for io_uring ring write events.
 * @version 0.0
 * @date 2025-09-11
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef IO_URING_RING_WRITE_RESPONSE_H
#define IO_URING_RING_WRITE_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (io_uring_ring_write_response)
 * ─────────────────────────────────────────────
 * {
 *   "event": "IO_URING_RING_WRITE",
 *   "vcpu_id": 0,
 *   "regs": {
 *     "rip": "0xfffff80000010234",
 *     "rsp": "0xfffff8000010ff00",
 *     "cr3": "0x0000000123456000"
 *   },
 *   "io_uring": {
 *     "breakpoint_addr": "0xfffff80000234567",
 *     "pt_regs_addr": "0xfffff80000345678",
 *     "syscall": {
 *       "number": 426,
 *       "name": "__x64_sys_io_uring_enter",
 *       "user_ip": "0x00007f1234567890"
 *     },
 *     "arguments": {
 *       "file_descriptor": 3,
 *       "to_submit": 1,
 *       "min_complete": 0,
 *       "flags": "0x00000001",
 *       "sig_ptr": "0x0000000000000000",
 *       "sigsz": 0
 *     }
 *   }
 * }
 */

/**
 * @brief Event payload for an io_uring ring write (system call interception).
 */
typedef struct io_uring_ring_write_data {
  uint32_t vcpu_id;  ///< Identifier of the vCPU that triggered the event.
  uint64_t rip;      ///< Instruction pointer (RIP) at the time of the event.
  uint64_t rsp;      ///< Stack pointer (RSP) at the time of the event.
  uint64_t cr3;      ///< CR3 register value at the time of the event.
  uint64_t breakpoint_addr;  ///< Address where the breakpoint was triggered.
  uint64_t pt_regs_addr;     ///< Address of the pt_regs structure.
  unsigned int file_descriptor;  ///< io_uring file descriptor.
  unsigned int to_submit;        ///< Number of entries to submit.
  unsigned int min_complete;     ///< Minimum number of completions to wait for.
  unsigned int flags;            ///< io_uring_enter flags.
  uint64_t sig_ptr;              ///< Pointer to signal set.
  size_t sigsz;                  ///< Size of signal set.
  unsigned long user_ip;         ///< User-space instruction pointer.
  unsigned long syscall_number;  ///< System call number.
} io_uring_ring_write_data_t;

/**
 * @brief Allocate and initialize a new io_uring ring write data object.
 *
 * @param vcpu_id The vCPU identifier.
 * @param rip The RIP register value.
 * @param rsp The RSP register value.
 * @param cr3 The CR3 register value.
 * @param breakpoint_addr The address where the breakpoint was triggered.
 * @param pt_regs_addr The address of the pt_regs structure.
 * @param file_descriptor The io_uring file descriptor.
 * @param to_submit Number of entries to submit.
 * @param min_complete Minimum number of completions.
 * @param flags io_uring_enter flags.
 * @param sig_ptr Pointer to signal set.
 * @param sigsz Size of signal set.
 * @param user_ip User-space instruction pointer.
 * @param syscall_number System call number.
 * @return Pointer to a newly allocated io_uring_ring_write_data_t, or NULL on failure.
 */
io_uring_ring_write_data_t* io_uring_ring_write_data_new(
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3,
    uint64_t breakpoint_addr, uint64_t pt_regs_addr,
    unsigned int file_descriptor, unsigned int to_submit,
    unsigned int min_complete, unsigned int flags, uint64_t sig_ptr,
    size_t sigsz, unsigned long user_ip, unsigned long syscall_number);

/**
 * @brief Free an io_uring ring write data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void io_uring_ring_write_data_free(io_uring_ring_write_data_t* data);

/**
 * @brief Serialize an io_uring ring write data object to JSON.
 *
 * @param data Pointer to the io_uring ring write data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* io_uring_ring_write_data_to_json(const io_uring_ring_write_data_t* data);

#endif  // IO_URING_RING_WRITE_RESPONSE_H