/**
 * @file idt_write_response.h
 * @brief Response structure for IDT write events.
 * @version 0.1
 * @date 2025-09-11
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef IDT_WRITE_RESPONSE_H
#define IDT_WRITE_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (idt_write_response)
 * ─────────────────────────────────────────────
 * {
 *   "event": "IDT_WRITE",
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
 * @brief Event payload for an IDT (Interrupt Descriptor Table) write.
 */
typedef struct idt_write_data {
  uint32_t vcpu_id;    ///< Identifier of the vCPU that triggered the event.
  uint64_t rip;        ///< Instruction pointer (RIP) at the time of the event.
  uint64_t rsp;        ///< Stack pointer (RSP) at the time of the event.
  uint64_t cr3;        ///< CR3 register value at the time of the event.
  uint64_t write_gla;  ///< Guest linear address of the IDT write operation.
  uint64_t write_gpa;  ///< Guest physical address of the IDT write operation.
} idt_write_data_t;

/**
 * @brief Allocate and initialize a new IDT write data object.
 *
 * @param vcpu_id The vCPU identifier.
 * @param rip The RIP register value.
 * @param rsp The RSP register value.
 * @param cr3 The CR3 register value.
 * @param write_gla The guest linear address of the write.
 * @param write_gpa The guest physical address of the write.
 * @return Pointer to a newly allocated idt_write_data_t, or NULL on failure.
 */
idt_write_data_t* idt_write_data_new(uint32_t vcpu_id, uint64_t rip,
                                     uint64_t rsp, uint64_t cr3,
                                     uint64_t write_gla, uint64_t write_gpa);

/**
 * @brief Free an IDT write data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void idt_write_data_free(idt_write_data_t* data);

/**
 * @brief Serialize an IDT write data object to JSON.
 *
 * @param data Pointer to the IDT write data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* idt_write_data_to_json(const idt_write_data_t* data);

#endif  // IDT_WRITE_RESPONSE_H