/**
 * @file msr_registers_response.h
 * @brief Response structure and functions for MSR registers state analysis.
 * @version 0.0
 * @date 2025-01-27
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef MSR_REGISTERS_RESPONSE_H
#define MSR_REGISTERS_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (msr_registers_state_response)
 * ─────────────────────────────────────────────
 * {
 *   "state": "MSR_REGISTERS",
 *   "kernel_range": {
 *     "start": "0xffffffff81000000",
 *     "end": "0xffffffff82000000"
 *   },
 *   "legitimate_syscall_entry": {
 *     "address": "0xffffffff81000000",
 *     "symbol": "entry_SYSCALL_64",
 *     "found": true
 *   },
 *   "vcpus": [
 *     {
 *       "vcpu_id": 0,
 *       "msr_lstar": "0xffffffff81000000",
 *       "is_in_kernel_text": true,
 *       "matches_legitimate": true,
 *       "is_suspicious": false
 *     }
 *   ],
 *   "summary": {
 *     "total_vcpus": 4,
 *     "suspicious_vcpus": 0,
 *     "kernel_text_start": "0xffffffff81000000",
 *     "kernel_text_end": "0xffffffff82000000"
 *   }
 * }
 */

/**
 * @brief Information about a vCPU's MSR_LSTAR register.
 */
typedef struct vcpu_msr_info {
  uint32_t vcpu_id;         ///< vCPU identifier
  uint64_t msr_lstar;       ///< MSR_LSTAR value
  bool is_in_kernel_text;   ///< True if MSR_LSTAR points to kernel text
  bool matches_legitimate;  ///< True if matches expected syscall entry
  bool is_suspicious;       ///< True if vCPU appears suspicious
} vcpu_msr_info_t;

/**
 * @brief Information about the legitimate syscall entry point.
 */
typedef struct legitimate_syscall_entry {
  uint64_t address;  ///< Address of the legitimate syscall entry
  char* symbol;      ///< Symbol name (e.g., "entry_SYSCALL_64")
  bool found;        ///< True if legitimate entry was found
} legitimate_syscall_entry_t;

/**
 * @brief Summary information for MSR registers analysis.
 */
typedef struct msr_registers_summary {
  uint32_t total_vcpus;        ///< Total number of vCPUs analyzed
  uint32_t suspicious_vcpus;   ///< Number of suspicious vCPUs
  uint64_t kernel_text_start;  ///< Start of kernel text section
  uint64_t kernel_text_end;    ///< End of kernel text section
} msr_registers_summary_t;

/**
 * @brief State data for MSR registers analysis.
 */
typedef struct msr_registers_state_data {
  uint64_t kernel_start;  ///< Kernel text section start
  uint64_t kernel_end;    ///< Kernel text section end
  legitimate_syscall_entry_t
      legitimate_entry;             ///< Legitimate syscall entry info
  GArray* vcpus;                    ///< Array of vcpu_msr_info_t
  msr_registers_summary_t summary;  ///< Summary information
} msr_registers_state_data_t;

/**
 * @brief Allocate and initialize a new MSR registers state data object.
 *
 * @return Pointer to a newly allocated msr_registers_state_data_t, or NULL on failure.
 */
msr_registers_state_data_t* msr_registers_state_data_new(void);

/**
 * @brief Free an MSR registers state data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void msr_registers_state_data_free(msr_registers_state_data_t* data);

/**
 * @brief Set the kernel text section range.
 *
 * @param data The MSR registers state data object.
 * @param kernel_start Start address of kernel text section.
 * @param kernel_end End address of kernel text section.
 */
void msr_registers_state_set_kernel_range(msr_registers_state_data_t* data,
                                          uint64_t kernel_start,
                                          uint64_t kernel_end);

/**
 * @brief Set the legitimate syscall entry information.
 *
 * @param data The MSR registers state data object.
 * @param address Address of the legitimate syscall entry.
 * @param symbol Symbol name of the legitimate syscall entry.
 * @param found Whether the legitimate entry was found.
 */
void msr_registers_state_set_legitimate_entry(msr_registers_state_data_t* data,
                                              uint64_t address,
                                              const char* symbol, bool found);

/**
 * @brief Add vCPU MSR information.
 *
 * @param data The MSR registers state data object.
 * @param vcpu_id vCPU identifier.
 * @param msr_lstar MSR_LSTAR value.
 * @param is_in_kernel_text Whether MSR_LSTAR points to kernel text.
 * @param matches_legitimate Whether MSR_LSTAR matches expected entry.
 * @param is_suspicious Whether the vCPU appears suspicious.
 */
void msr_registers_state_add_vcpu(msr_registers_state_data_t* data,
                                  uint32_t vcpu_id, uint64_t msr_lstar,
                                  bool is_in_kernel_text,
                                  bool matches_legitimate, bool is_suspicious);

/**
 * @brief Set the summary information.
 *
 * @param data The MSR registers state data object.
 * @param total_vcpus Total number of vCPUs.
 * @param suspicious_vcpus Number of suspicious vCPUs.
 */
void msr_registers_state_set_summary(msr_registers_state_data_t* data,
                                     uint32_t total_vcpus,
                                     uint32_t suspicious_vcpus);

/**
 * @brief Serialize an MSR registers state data object to JSON.
 *
 * @param data Pointer to the MSR registers state data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* msr_registers_state_data_to_json(const msr_registers_state_data_t* data);

#endif  // MSR_REGISTERS_RESPONSE_H
