/**
 * @file page_table_modification_response.h
 * @brief Response structure and functions for page table modification events.
 * @version 0.0
 * @date 2025-09-11
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef PAGE_TABLE_MODIFICATION_RESPONSE_H
#define PAGE_TABLE_MODIFICATION_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (page_table_modification_response)
 * ─────────────────────────────────────────────
 * {
 *   "event": "PAGE_TABLE_MODIFICATION",
 *   "vcpu_id": 0,
 *   "regs": {
 *     "rip": "0xfffff80000010234",
 *     "rsp": "0xfffff8000010ff00",
 *     "cr3": "0x0000000123456000"
 *   },
 *   "page_table": {
 *     "pml4_pa": "0x0000000123456000",
 *     "modifications": [
 *       {
 *         "index": 123,
 *         "old_entry": "0x0000000000000000",
 *         "new_entry": "0x0000000123456003",
 *         "old_flags": {
 *           "present": false,
 *           "writable": false,
 *           "user": false,
 *           "noexec": false
 *         },
 *         "new_flags": {
 *           "present": true,
 *           "writable": true,
 *           "user": false,
 *           "noexec": false
 *         }
 *       }
 *     ]
 *   }
 * }
 */

/**
 * @brief Flags for a page table entry.
 */
typedef struct pt_entry_flags {
  bool present;   ///< Page present bit.
  bool writable;  ///< Page writable bit.
  bool user;      ///< User-mode accessible bit.
  bool noexec;    ///< No-execute bit.
} pt_entry_flags_t;

/**
 * @brief Information about a single page table entry modification.
 */
typedef struct pt_entry_modification {
  uint32_t index;              ///< Index of the modified entry.
  uint64_t old_entry;          ///< Previous entry value.
  uint64_t new_entry;          ///< New entry value.
  pt_entry_flags_t old_flags;  ///< Decoded flags from old entry.
  pt_entry_flags_t new_flags;  ///< Decoded flags from new entry.
} pt_entry_modification_t;

/**
 * @brief Event payload for a page table modification.
 */
typedef struct page_table_modification_data {
  uint32_t vcpu_id;  ///< Identifier of the vCPU that triggered the event.
  uint64_t rip;      ///< Instruction pointer (RIP) at the time of the event.
  uint64_t rsp;      ///< Stack pointer (RSP) at the time of the event.
  uint64_t cr3;      ///< CR3 register value at the time of the event.
  uint64_t pml4_pa;  ///< Physical address of the PML4 table.
  GArray* modifications;  ///< Array of pt_entry_modification_t structs.
} page_table_modification_data_t;

/**
 * @brief Allocate and initialize a new page table modification data object.
 *
 * @param vcpu_id The vCPU identifier.
 * @param rip The RIP register value.
 * @param rsp The RSP register value.
 * @param cr3 The CR3 register value.
 * @param pml4_pa The physical address of the PML4 table.
 * @return Pointer to a newly allocated page_table_modification_data_t, or NULL on failure.
 */
page_table_modification_data_t* page_table_modification_data_new(
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3,
    uint64_t pml4_pa);

/**
 * @brief Add a page table entry modification to the data structure.
 *
 * @param data The page table modification data object.
 * @param index The index of the modified entry.
 * @param old_entry The old entry value.
 * @param new_entry The new entry value.
 * @param old_present Old present flag.
 * @param new_present New present flag.
 * @param old_writable Old writable flag.
 * @param new_writable New writable flag.
 * @param old_user Old user flag.
 * @param new_user New user flag.
 * @param old_noexec Old noexec flag.
 * @param new_noexec New noexec flag.
 */
void page_table_modification_add_entry(page_table_modification_data_t* data,
                                       uint32_t index, uint64_t old_entry,
                                       uint64_t new_entry, bool old_present,
                                       bool new_present, bool old_writable,
                                       bool new_writable, bool old_user,
                                       bool new_user, bool old_noexec,
                                       bool new_noexec);

/**
 * @brief Free a page table modification data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void page_table_modification_data_free(page_table_modification_data_t* data);

/**
 * @brief Serialize a page table modification data object to JSON.
 *
 * @param data Pointer to the page table modification data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* page_table_modification_data_to_json(
    const page_table_modification_data_t* data);

#endif  // PAGE_TABLE_MODIFICATION_RESPONSE_H