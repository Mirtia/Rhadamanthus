#ifndef MSR_WRITE_RESPONSE_H
#define MSR_WRITE_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (msr_write_response)
 * ─────────────────────────────────────────────
 * {
 *   "event": "MSR_WRITE",
 *   "vcpu_id": 0,
 *   "regs": {
 *     "rip": "0xfffff80000010234",
 *     "rsp": "0xfffff8000010ff00",
 *     "cr3": "0x0000000123456000"
 *   },
 *   "msr": {
 *     "index": "0x00000000c0000082",
 *     "value": "0xfffff80000234567",
 *     "name": "IA32_LSTAR",
 *     "note": true
 *   }
 * }
 */

/**
 * @brief Common security-relevant MSR indices
 */
#define MSR_IA32_LSTAR 0xC0000082           ///< System call entry point
#define MSR_IA32_CSTAR 0xC0000083           ///< Compat mode system call entry
#define MSR_IA32_FMASK 0xC0000084           ///< System call flag mask
#define MSR_IA32_KERNEL_GS_BASE 0xC0000102  ///< Kernel GS base
#define MSR_IA32_SYSENTER_CS 0x00000174     ///< SYSENTER CS
#define MSR_IA32_SYSENTER_ESP 0x00000175    ///< SYSENTER ESP
#define MSR_IA32_SYSENTER_EIP 0x00000176    ///< SYSENTER EIP
#define MSR_IA32_EFER 0xC0000080  ///< Extended feature enable register
#define MSR_IA32_STAR 0xC0000081  ///< System call target address

/**
 * @brief Event payload for an MSR write.
 */
typedef struct msr_write_data {
  uint32_t vcpu_id;    ///< Identifier of the vCPU that triggered the event.
  uint64_t rip;        ///< Instruction pointer (RIP) at the time of the event.
  uint64_t rsp;        ///< Stack pointer (RSP) at the time of the event.
  uint64_t cr3;        ///< CR3 register value at the time of the event.
  uint64_t msr_index;  ///< MSR index that was written to.
  uint64_t msr_value;  ///< Value written to the MSR.
  char* msr_name;      ///< Human-readable name of the MSR (if known).
  bool note;           ///< Mark if it needs special attention.
} msr_write_data_t;

/**
 * @brief Allocate and initialize a new MSR write data object.
 *
 * @param vcpu_id The vCPU identifier.
 * @param rip The RIP register value.
 * @param rsp The RSP register value.
 * @param cr3 The CR3 register value.
 * @param msr_index The MSR index.
 * @param msr_value The MSR value.
 * @return Pointer to a newly allocated msr_write_data_t, or NULL on failure.
 */
msr_write_data_t* msr_write_data_new(uint32_t vcpu_id, uint64_t rip,
                                     uint64_t rsp, uint64_t cr3,
                                     uint64_t msr_index, uint64_t msr_value);

/**
 * @brief Free an MSR write data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void msr_write_data_free(msr_write_data_t* data);

/**
 * @brief Get the human-readable name for an MSR index.
 *
 * @param msr_index The MSR index.
 * @return String name of the MSR, or NULL if unknown.
 */
const char* msr_get_name(uint64_t msr_index);

/**
 * @brief Check if an MSR write is security-relevant.
 *
 * @param msr_index The MSR index.
 * @return true if the MSR is security-relevant, false otherwise.
 */
bool msr_is_note(uint64_t msr_index);

/**
 * @brief Serialize an MSR write data object to JSON.
 *
 * @param data Pointer to the MSR write data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* msr_write_data_to_json(const msr_write_data_t* data);

#endif  // MSR_WRITE_RESPONSE_H