/**
 * @file kallsyms_symbols_response.h
 * @brief Response structure and functions for kallsyms symbols state analysis.
 * @version 0.0
 * @date 2025-01-27
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef KALLSYMS_SYMBOLS_RESPONSE_H
#define KALLSYMS_SYMBOLS_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (kallsyms_symbols_state_response)
 * ─────────────────────────────────────────────
 * {
 *   "state": "KALLSYMS_SYMBOLS",
 *   "symbols": [
 *     {
 *       "address": "0xffffffff81000000",
 *       "type": "T",
 *       "name": "start_kernel",
 *       "module": null
 *     }
 *   ],
 *   "summary": {
 *     "total_symbols": 150000,
 *     "returned_symbols": 150000,
 *     "kptr_restrict": 0,
 *     "filters": {
 *       "name_regex": "",
 *       "module_regex": "",
 *       "max_symbols": null
 *     },
 *     "statistics": {
 *       "reachable": 120000,
 *       "zero_addr": 5000,
 *       "name_fail": 0,
 *       "addr_fail": 0,
 *       "in_text": 100000,
 *       "outside_text": 50000
 *     }
 *   }
 * }
 */

/**
 * @brief Information about a kernel symbol.
 */
typedef struct kallsyms_symbol_info {
  char* address;  ///< Symbol address (hex string)
  char* type;     ///< Symbol type (T, t, D, d, etc.)
  char* name;     ///< Symbol name
  char* module;   ///< Module name (NULL if kernel symbol)
} kallsyms_symbol_info_t;

/**
 * @brief Filter information for kallsyms analysis.
 */
typedef struct kallsyms_filters {
  char* name_regex;     ///< Name filter regex
  char* module_regex;   ///< Module filter regex
  int32_t max_symbols;  ///< Maximum symbols to return (-1 if unlimited)
} kallsyms_filters_t;

/**
 * @brief Statistics for kallsyms analysis.
 */
typedef struct kallsyms_statistics {
  uint32_t reachable;     ///< Number of reachable symbols
  uint32_t zero_addr;     ///< Number of symbols with zero address
  uint32_t name_fail;     ///< Number of name decompression failures
  uint32_t addr_fail;     ///< Number of address resolution failures
  uint32_t in_text;       ///< Number of symbols in kernel text section
  uint32_t outside_text;  ///< Number of symbols outside kernel text section
} kallsyms_statistics_t;

/**
 * @brief Summary information for kallsyms symbols analysis.
 */
typedef struct kallsyms_symbols_summary {
  uint32_t total_symbols;            ///< Total number of symbols found
  uint32_t returned_symbols;         ///< Number of symbols returned in response
  int32_t kptr_restrict;             ///< kptr_restrict value (-1 if unknown)
  kallsyms_filters_t filters;        ///< Applied filters
  kallsyms_statistics_t statistics;  ///< Analysis statistics
} kallsyms_symbols_summary_t;

/**
 * @brief State data for kallsyms symbols analysis.
 */
typedef struct kallsyms_symbols_state_data {
  GArray* symbols;                     ///< Array of kallsyms_symbol_info_t
  kallsyms_symbols_summary_t summary;  ///< Summary information
} kallsyms_symbols_state_data_t;

/**
 * @brief Allocate and initialize a new kallsyms symbols state data object.
 *
 * @return Pointer to a newly allocated kallsyms_symbols_state_data_t, or NULL on failure.
 */
kallsyms_symbols_state_data_t* kallsyms_symbols_state_data_new(void);

/**
 * @brief Free a kallsyms symbols state data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void kallsyms_symbols_state_data_free(kallsyms_symbols_state_data_t* data);

/**
 * @brief Add a kernel symbol to the list.
 *
 * @param data The kallsyms symbols state data object.
 * @param address Symbol address (hex string).
 * @param type Symbol type.
 * @param name Symbol name.
 * @param module Module name (can be NULL).
 */
void kallsyms_symbols_state_add_symbol(kallsyms_symbols_state_data_t* data,
                                       const char* address, const char* type,
                                       const char* name, const char* module);

/**
 * @brief Set the summary information.
 *
 * @param data The kallsyms symbols state data object.
 * @param total_symbols Total number of symbols.
 * @param returned_symbols Number of symbols returned.
 * @param kptr_restrict kptr_restrict value (-1 if unknown).
 * @param name_regex Name filter regex (can be NULL).
 * @param module_regex Module filter regex (can be NULL).
 * @param max_symbols Maximum symbols limit (-1 if unlimited).
 * @param reachable Number of reachable symbols.
 * @param zero_addr Number of zero address symbols.
 * @param name_fail Number of name failures.
 * @param addr_fail Number of address failures.
 * @param in_text Number of symbols in kernel text.
 * @param outside_text Number of symbols outside kernel text.
 */
void kallsyms_symbols_state_set_summary(
    kallsyms_symbols_state_data_t* data, uint32_t total_symbols,
    uint32_t returned_symbols, int32_t kptr_restrict, const char* name_regex,
    const char* module_regex, int32_t max_symbols, uint32_t reachable,
    uint32_t zero_addr, uint32_t name_fail, uint32_t addr_fail,
    uint32_t in_text, uint32_t outside_text);

/**
 * @brief Serialize a kallsyms symbols state data object to JSON.
 *
 * @param data Pointer to the kallsyms symbols state data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* kallsyms_symbols_state_data_to_json(
    const kallsyms_symbols_state_data_t* data);

#endif  // KALLSYMS_SYMBOLS_RESPONSE_H
