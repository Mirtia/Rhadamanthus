/**
 * @file code_section_modify_response.h
 * @brief Response structure and functions for code section modify events.
 * @version 0.0
 * @date 2025-09-09
 * 
 * @copyright GNU Lesser General Public License v2.1
 */

#ifndef CODE_SECTION_MODIFY_RESPONSE_H
#define CODE_SECTION_MODIFY_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib.h>
#include <libvmi/libvmi.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (code_section_modify_response)
 * ─────────────────────────────────────────────
 * {
 *   "event": "CODE_SECTION_MODIFY",
 *   "vcpu_id": 0,
 *   "regs": {
 *     "rip": "0xfffff80000010234",
 *     "rsp": "0xfffff8000010ff00",
 *     "cr3": "0x0000000123456000"
 *   },
 *   "memory": {
 *     "write_gla": "0xfffff80000234567",
 *     "write_gpa": "0x0000000012345678"
 *   },
 *   "kernel_symbol": "sys_call_table"
 * }
 */

/**
 * @brief The structure representing a code section modify event.
 * 
 */
typedef struct {
  uint32_t vcpu_id;     ///< Virtual CPU identifier.
  uint64_t rip;         ///< Instruction pointer register value.
  uint64_t rsp;         ///< Stack pointer register value.
  uint64_t cr3;         ///< CR3 value.
  addr_t write_gla;     ///< Guest linear address of the write.
  addr_t write_gpa;     ///< Guest physical address of the write.
  char* kernel_symbol;  ///< Resolved kernel symbol name (can be NULL).
} code_section_modify_data_t;

/**
 * @brief Create a new code section modify data structure
 * 
 * @param vcpu_id Virtual CPU identifier
 * @param rip Instruction pointer register value
 * @param rsp Stack pointer register value 
 * @param cr3 CR3 value
 * @param write_gla Guest linear address of the write
 * @param write_gpa Guest physical address of the write
 * @param kernel_symbol Resolved kernel symbol name (can be NULL)
 * @return code_section_modify_data_t* Pointer to allocated structure or NULL on failure
 */
code_section_modify_data_t* code_section_modify_data_new(
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3,
    addr_t write_gla, addr_t write_gpa, const char* kernel_symbol);

/**
 * @brief Free code section modify data structure
 * 
 * @param data Pointer to the structure to free
 */
void code_section_modify_data_free(code_section_modify_data_t* data);

/**
 * @brief Convert code section modify data to JSON representation
 * 
 * @param data Pointer to the data structure
 * @return cJSON* JSON object or NULL on failure
 */
cJSON* code_section_modify_data_to_json(const code_section_modify_data_t* data);

#endif  // CODE_SECTION_MODIFY_RESPONSE_H