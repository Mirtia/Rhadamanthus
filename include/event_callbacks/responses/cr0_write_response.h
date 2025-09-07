#ifndef CR0_WRITE_RESPONSE_H
#define CR0_WRITE_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (cr0_write_response)
 * ─────────────────────────────────────────────
 * {
 *   "event": "CR0_WRITE",
 *   "vcpu_id": 0,
 *   "regs": {
 *     "rip": "0xfffff80000010234",
 *     "rsp": "0xfffff8000010ff00",
 *     "cr3": "0x0000000123456000"
 *   },
 *   "cr0": {
 *     "new": "0x80050033",
 *     "old": "0x80050013",
 *     "flags": {
 *       "PE": true,
 *       "WP": true,
 *       "AM": false,
 *       "CD": false,
 *       "PG": true
 *     }
 *   }
 * }
 */

#ifndef CR0_PE
#define CR0_PE (1ULL << 0)  ///< Protected mode enable (bit 0)
#endif
#ifndef CR0_WP
#define CR0_WP (1ULL << 16)  ///< Write protect (bit 16)
#endif
#ifndef CR0_AM
#define CR0_AM (1ULL << 18)  ///< Alignment mask (bit 18)
#endif
#ifndef CR0_CD
#define CR0_CD (1ULL << 30)  ///< Cache disable (bit 30)
#endif
#ifndef CR0_PG
#define CR0_PG (1ULL << 31)  ///< Paging enable (bit 31)
#endif

/**
 * @brief Decoded flag view of the CR0 control register.
 */
typedef struct cr0_flags {
  bool PE;  ///< Protected mode enable (CR0.PE).
  bool WP;  ///< Write protect (CR0.WP).
  bool AM;  ///< Alignment mask (CR0.AM).
  bool CD;  ///< Cache disable (CR0.CD).
  bool PG;  ///< Paging enable (CR0.PG).
} cr0_flags_t;

/**
 * @brief CR0 transition values (old may be unknown).
 */
typedef struct cr0_transition {
  uint64_t new_val;  ///< New CR0 value after the write.
  uint64_t old_val;  ///< Previous CR0 value, valid only if has_old is true.
  bool has_old;      ///< Whether old_val contains a valid previous CR0 value.
} cr0_transition_t;

/**
 * @brief Event payload for a CR0 write.
 */
typedef struct cr0_write_data {
  uint32_t vcpu_id;  ///< Identifier of the vCPU that triggered the event.
  uint64_t rip;      ///< Instruction pointer (RIP) at the time of the event.
  uint64_t rsp;      ///< Stack pointer (RSP) at the time of the event.
  uint64_t cr3;      ///< CR3 register value at the time of the event.

  cr0_transition_t cr0;  ///< New (and optionally old) CR0 values.
  cr0_flags_t flags;     ///< Decoded CR0 flags from the new CR0 value.
} cr0_write_data_t;

/**
 * @brief Allocate and initialize a new CR0 write data object.
 *
 * @param vcpu_id The vCPU identifier.
 * @param rip The RIP register value.
 * @param rsp The RSP register value.
 * @param cr3 The CR3 register value.
 * @param cr0_new The new CR0 value after the write.
 * @param has_old Whether the old CR0 value is available.
 * @param cr0_old The old CR0 value (valid only if has_old is true).
 * @return Pointer to a newly allocated cr0_write_data_t, or NULL on failure.
 */
cr0_write_data_t* cr0_write_data_new(uint32_t vcpu_id, uint64_t rip,
                                     uint64_t rsp, uint64_t cr3,
                                     uint64_t cr0_new, bool has_old,
                                     uint64_t cr0_old);

/**
 * @brief Free a CR0 write data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void cr0_write_data_free(cr0_write_data_t* data);

/**
 * @brief Decode CR0 bits into a cr0_flags_t structure.
 *
 * @param cr0 The CR0 register value.
 * @param out_flags Pointer to the output structure to populate.
 */
void cr0_decode_flags(uint64_t cr0, cr0_flags_t* out_flags);

/**
 * @brief Serialize a CR0 write data object to JSON.
 *
 * @param data Pointer to the CR0 write data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* cr0_write_data_to_json(const cr0_write_data_t* data);

/**
 * @brief Add a uint64_t value to a cJSON object as a zero-padded hex string.
 *
 * @param parent Parent cJSON object.
 * @param key Key to use for the new field.
 * @param value Value to format as hex.
 */
void cjson_add_hex_u64(cJSON* parent, const char* key, uint64_t value);

/**
 * @brief Add a boolean value to a cJSON object.
 *
 * @param parent Parent cJSON object.
 * @param key Key to use for the new field.
 * @param value Boolean value to add.
 */
void cjson_add_bool(cJSON* parent, const char* key, bool value);

#endif  // CR0_WRITE_RESPONSE_H
