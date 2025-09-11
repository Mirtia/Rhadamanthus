/**
 * @file kallsyms_symbols.h
 * @brief This file contains the callback function to enumerate kernel symbols from in-memory kallsyms arrays.
 * @version 0.0
 * @date 2025-08-24
 * 
 * @copyright GNU Lesser General Public License v2.1
 */
#ifndef KALLSYMS_SYMBOLS_H
#define KALLSYMS_SYMBOLS_H

#include <libvmi/libvmi.h>
#include <stdint.h>

/**
 * @brief Enumerate kernel symbols from in-memory kallsyms arrays.
 *
 * Reads `kallsyms_num_syms`, `kallsyms_names`, `kallsyms_token_table`,
 * `kallsyms_token_index`, and either `kallsyms_addresses` or
 * (`kallsyms_offsets` + `kallsyms_relative_base`). Decompresses each
 * symbol name, reconstructs its virtual address, and checks whether the
 * address is readable. Optionally classifies addresses as inside or
 * outside the kernel text range (`_stext.._etext`).
 *
 * This bypasses `/proc/kallsyms` filtering and helps detect hidden or
 * invalid symbols. Logs a sample set and summary statistics
 * (total, reachable, failures, in/out of text).
 *
 * @param vmi     The VMI instance.
 * @param context User-defined context (unused)
 * @return uint32_t VMI_SUCCESS on successful inspection, else VMI_FAILURE.
 */
uint32_t state_kallsyms_symbols_callback(vmi_instance_t vmi, void* context);

#endif  // KALLSYMS_SYMBOLS_H
