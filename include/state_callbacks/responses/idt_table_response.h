#ifndef IDT_TABLE_RESPONSE_H
#define IDT_TABLE_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (idt_table_state_response)
 * ─────────────────────────────────────────────
 * {
 *   "state": "IDT_TABLE",
 *   "kernel_range": {
 *     "start": "0xffffffff81000000",
 *     "end": "0xffffffff82000000"
 *   },
 *   "vcpus": [
 *     {
 *       "vcpu_id": 0,
 *       "idt_base": "0xffffffff81e01000"
 *     }
 *   ],
 *   "handlers": [
 *     {
 *       "vcpu_id": 0,
 *       "vector": 14,
 *       "name": "page_fault",
 *       "handler_address": "0xffffffff81050123",
 *       "is_hooked": false
 *     }
 *   ],
 *   "summary": {
 *     "total_hooked_handlers": 0,
 *     "vcpu_inconsistency": false,
 *   }
 * }
 */

/**
 * @brief Information about a vCPU's IDT configuration.
 */
typedef struct vcpu_idt_info {
  uint32_t vcpu_id;   ///< vCPU identifier
  uint64_t idt_base;  ///< IDTR base address for this vCPU
} vcpu_idt_info_t;

/**
 * @brief Information about an interrupt handler.
 */
typedef struct idt_handler_info {
  uint32_t vcpu_id;          ///< vCPU where this handler was found
  uint16_t vector;           ///< Interrupt vector number
  char* name;                ///< Human-readable name of the interrupt
  uint64_t handler_address;  ///< Address of the handler function
  bool is_hooked;  ///< True if handler is outside kernel text (suspicious)
} idt_handler_info_t;

/**
 * @brief State data for IDT table analysis.
 */
typedef struct idt_table_state_data {
  uint64_t kernel_start;    ///< Start of kernel text section
  uint64_t kernel_end;      ///< End of kernel text section
  GArray* vcpu_infos;       ///< Array of vcpu_idt_info_t
  GArray* handlers;         ///< Array of idt_handler_info_t
  int total_hooked;         ///< Total number of hooked handlers detected
  bool vcpu_inconsistency;  ///< True if IDT bases differ across vCPUs
} idt_table_state_data_t;

/**
 * @brief Allocate and initialize a new IDT table state data object.
 *
 * @return Pointer to a newly allocated idt_table_state_data_t, or NULL on failure.
 */
idt_table_state_data_t* idt_table_state_data_new(void);

/**
 * @brief Set the kernel text section range.
 *
 * @param data The IDT state data object.
 * @param kernel_start Start address of kernel text section.
 * @param kernel_end End address of kernel text section.
 */
void idt_table_state_set_kernel_range(idt_table_state_data_t* data,
                                      uint64_t kernel_start,
                                      uint64_t kernel_end);

/**
 * @brief Add vCPU IDT information.
 *
 * @param data The IDT state data object.
 * @param vcpu_id The vCPU identifier.
 * @param idt_base The IDTR base address.
 */
void idt_table_state_add_vcpu_info(idt_table_state_data_t* data,
                                   uint32_t vcpu_id, uint64_t idt_base);

/**
 * @brief Add interrupt handler information.
 *
 * @param data The IDT state data object.
 * @param vcpu_id The vCPU identifier.
 * @param vector The interrupt vector.
 * @param name The interrupt name.
 * @param handler_address The handler address.
 * @param is_hooked Whether the handler appears to be hooked.
 */
void idt_table_state_add_hooked_handler(idt_table_state_data_t* data,
                                        uint32_t vcpu_id, uint16_t vector,
                                        const char* name,
                                        uint64_t handler_address,
                                        bool is_hooked);

/**
 * @brief Set summary information.
 *
 * @param data The IDT state data object.
 * @param total_hooked Total number of hooked handlers.
 * @param vcpu_inconsistency Whether vCPUs have inconsistent IDT bases.
 */
void idt_table_state_set_summary(idt_table_state_data_t* data, int total_hooked,
                                 bool vcpu_inconsistency);

/**
 * @brief Free an IDT table state data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void idt_table_state_data_free(idt_table_state_data_t* data);

/**
 * @brief Serialize an IDT table state data object to JSON.
 *
 * @param data Pointer to the IDT table state data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* idt_table_state_data_to_json(const idt_table_state_data_t* data);

#endif  // IDT_TABLE_RESPONSE_H