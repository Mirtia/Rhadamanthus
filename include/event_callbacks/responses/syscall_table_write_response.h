/**
 * @file syscall_table_write_response.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2025-09-11
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef SYSCALL_TABLE_WRITE_RESPONSE_H
#define SYSCALL_TABLE_WRITE_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (syscall_table_write_response)
 * ─────────────────────────────────────────────
 * {
 *   "event": "SYSCALL_TABLE_WRITE",
 *   "vcpu_id": 0,
 *   "regs": {
 *     "rip": "0xfffff80000010234",
 *     "rsp": "0xfffff8000010ff00",
 *     "cr3": "0x0000000123456000"
 *   },
 *   "memory": {
 *     "write_gla": "0xfffff80000234567",
 *     "write_gpa": "0x0000000012345678"
 *   }
 * }
 */

/**
 * @brief Event payload for a syscall table write.
 */
typedef struct syscall_table_write_data {
  uint32_t vcpu_id;    ///< Identifier of the vCPU that triggered the event.
  uint64_t rip;        ///< Instruction pointer (RIP) at the time of the event.
  uint64_t rsp;        ///< Stack pointer (RSP) at the time of the event.
  uint64_t cr3;        ///< CR3 register value at the time of the event.
  uint64_t write_gla;  ///< Guest linear address of the write operation.
  uint64_t write_gpa;  ///< Guest physical address of the write operation.
} syscall_table_write_data_t;

/**
 * @brief Allocate and initialize a new syscall table write data object.
 *
 * @param vcpu_id The vCPU identifier.
 * @param rip The RIP register value.
 * @param rsp The RSP register value.
 * @param cr3 The CR3 register value.
 * @param write_gla The guest linear address of the write.
 * @param write_gpa The guest physical address of the write.
 * @return Pointer to a newly allocated syscall_table_write_data_t, or NULL on failure.
 */
syscall_table_write_data_t* syscall_table_write_data_new(
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3,
    uint64_t write_gla, uint64_t write_gpa);

/**
 * @brief Free a syscall table write data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void syscall_table_write_data_free(syscall_table_write_data_t* data);

/**
 * @brief Serialize a syscall table write data object to JSON.
 *
 * @param data Pointer to the syscall table write data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* syscall_table_write_data_to_json(const syscall_table_write_data_t* data);

#endif  // SYSCALL_TABLE_WRITE_RESPONSE_H