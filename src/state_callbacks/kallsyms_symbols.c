#include "state_callbacks/kallsyms_symbols.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "event_handler.h"
#include "state_callbacks/responses/kallsyms_symbols_response.h"
#include "utils.h"

#define KSYM_MAX_NAME 1024    // Max symbol name length.
#define TOKEN_TABLE_SIZE 256  // kallsyms token table size

/**
 * @brief Read the kallsyms token_index array for symbol name decompression
 * 
 * @param vmi VMI instance
 * @param a_tidx Address of kallsyms_token_index
 * @param token_index Output array of 256 uint16_t values
 * @return true on success, false on failure
 */
static bool read_token_index(vmi_instance_t vmi, addr_t a_tidx,
                             uint16_t token_index[TOKEN_TABLE_SIZE]) {
  for (int i = 0; i < TOKEN_TABLE_SIZE; i++) {
    if (vmi_read_16_va(vmi, a_tidx + (addr_t)(i * 2), 0, &token_index[i]) !=
        VMI_SUCCESS) {
      log_error(
          "STATE_KALLSYMS_SYMBOLS: Failed to read token_index at offset %d", i);
      return false;
    }
  }
  return true;
}

/**
 * @brief Decompress a kallsyms symbol name
 * 
 * kallsyms compresses symbol names using a token-based scheme.
 * Each symbol name is stored as: [length_byte] [token_0] [token_1] ... [token_N-1]
 * Each token is expanded by looking up characters in the token_table.
 * 
 * @param vmi VMI instance
 * @param token_index Pre-loaded token index array
 * @param names_cursor Current position in kallsyms_names array
 * @param token_table_addr Address of kallsyms_token_table
 * @param name_buf Output buffer for decompressed name
 * @param name_buf_size Size of output buffer
 * @param next_cursor Output: next position in kallsyms_names
 * @return true on success, false on failure
 */
static bool decompress_symbol_name(
    vmi_instance_t vmi, const uint16_t token_index[TOKEN_TABLE_SIZE],
    addr_t names_cursor,
    addr_t token_table_addr,  // NOLINT(bugprone-easily-swappable-parameters)
    char* name_buf, size_t name_buf_size, addr_t* next_cursor) {
  // Read compressed length
  uint8_t comp_len = 0;
  if (vmi_read_8_va(vmi, names_cursor, 0, &comp_len) != VMI_SUCCESS) {
    return false;
  }

  addr_t comp_codes = names_cursor + 1;
  size_t out_used = 0;

  // Expand each token
  for (uint32_t k = 0; k < comp_len; k++) {
    uint8_t code = 0;
    if (vmi_read_8_va(vmi, comp_codes + k, 0, &code) != VMI_SUCCESS) {
      return false;
    }

    // Expand token by reading characters from token_table until NULL
    uint16_t off = token_index[code];
    addr_t tcur = token_table_addr + (addr_t)off;

    for (;;) {
      uint8_t chr = 0;
      if (vmi_read_8_va(vmi, tcur++, 0, &chr) != VMI_SUCCESS) {
        return false;
      }

      if (chr == 0) {
        break;  // End of token
      }

      if (out_used + 1 >= name_buf_size) {
        log_warn("STATE_KALLSYMS_SYMBOLS: Symbol name buffer overflow");
        return false;
      }

      name_buf[out_used++] = (char)chr;
    }
  }

  name_buf[out_used] = '\0';
  *next_cursor = comp_codes + comp_len;
  return true;
}

/**
 * @brief Resolve a kallsyms symbol address
 * 
 * Handles both relative and absolute address modes, and 32-bit vs 64-bit architectures.
 * 
 * @param vmi VMI instance
 * @param index Symbol index
 * @param use_relative Whether to use relative addressing mode
 * @param is_64 Whether the kernel is 64-bit
 * @param relbase64 Base address for relative mode
 * @param offsets_addr Address of kallsyms_offsets (for relative mode)
 * @param addresses_addr Address of kallsyms_addresses (for absolute mode)
 * @param virt_addr Output: resolved virtual address
 * @return true on success, false on failure
 */
static bool resolve_symbol_address(
    vmi_instance_t vmi, uint32_t index, bool use_relative,
    bool is_64,          // NOLINT(bugprone-easily-swappable-parameters)
    uint64_t relbase64,  // NOLINT(bugprone-easily-swappable-parameters)
    addr_t offsets_addr, addr_t addresses_addr, addr_t* virt_addr) {
  if (use_relative) {
    // Relative mode: read 32-bit signed offset and add to base
    uint32_t rel_u32 = 0;
    if (vmi_read_32_va(vmi, offsets_addr + (addr_t)(index * 4), 0, &rel_u32) !=
        VMI_SUCCESS) {
      return false;
    }
    int32_t rel = (int32_t)rel_u32;  // Treat as signed
    *virt_addr = (addr_t)((uint64_t)relbase64 + (int64_t)rel);
  } else {
    // Absolute mode: read address directly
    if (is_64) {
      uint64_t a64 = 0;
      if (vmi_read_64_va(vmi, addresses_addr + (addr_t)(index * 8), 0, &a64) !=
          VMI_SUCCESS) {
        return false;
      }
      *virt_addr = (addr_t)a64;
    } else {
      uint32_t a32 = 0;
      if (vmi_read_32_va(vmi, addresses_addr + (addr_t)(index * 4), 0, &a32) !=
          VMI_SUCCESS) {
        return false;
      }
      *virt_addr = (addr_t)a32;
    }
  }

  return true;
}

// NOLINTNEXTLINE
uint32_t state_kallsyms_symbols_callback(vmi_instance_t vmi, void* context) {
  // Preconditions
  if (!vmi || !context) {
    return log_error_and_queue_response_task(
        "kallsyms_symbols_state", STATE_KALLSYMS_SYMBOLS, INVALID_ARGUMENTS,
        "STATE_KALLSYMS_SYMBOLS: Invalid arguments to kallsyms symbols state "
        "callback");
  }

  event_handler_t* event_handler = (event_handler_t*)context;
  if (!event_handler || !event_handler->is_paused) {
    return log_error_and_queue_response_task(
        "kallsyms_symbols_state", STATE_KALLSYMS_SYMBOLS, INVALID_ARGUMENTS,
        "STATE_KALLSYMS_SYMBOLS: Callback requires a valid event handler "
        "context");
  }

  log_info("Executing STATE_KALLSYMS_SYMBOLS callback.");

  // Create kallsyms symbols state data structure
  kallsyms_symbols_state_data_t* symbols_data =
      kallsyms_symbols_state_data_new();
  if (!symbols_data) {
    return log_error_and_queue_response_task(
        "kallsyms_symbols_state", STATE_KALLSYMS_SYMBOLS,
        MEMORY_ALLOCATION_FAILURE,
        "STATE_KALLSYMS_SYMBOLS: Failed to allocate memory for kallsyms "
        "symbols state data");
  }

  // Detect guest pointer width.
  const bool is_64 = (vmi_get_page_mode(vmi, 0) == VMI_PM_IA32E);

  addr_t a_num = 0, a_names = 0, a_ttab = 0, a_tidx = 0;
  if (vmi_translate_ksym2v(vmi, "kallsyms_num_syms", &a_num) != VMI_SUCCESS ||
      vmi_translate_ksym2v(vmi, "kallsyms_names", &a_names) != VMI_SUCCESS ||
      vmi_translate_ksym2v(vmi, "kallsyms_token_table", &a_ttab) !=
          VMI_SUCCESS ||
      vmi_translate_ksym2v(vmi, "kallsyms_token_index", &a_tidx) !=
          VMI_SUCCESS) {
    kallsyms_symbols_state_data_free(symbols_data);
    return log_error_and_queue_response_task(
        "kallsyms_symbols_state", STATE_KALLSYMS_SYMBOLS, VMI_OP_FAILURE,
        "STATE_KALLSYMS_SYMBOLS: Failed to resolve one or more kallsyms "
        "arrays");
  }

  uint32_t num_syms = 0;
  if (vmi_read_32_va(vmi, a_num, 0, &num_syms) != VMI_SUCCESS ||
      num_syms == 0) {
    kallsyms_symbols_state_data_free(symbols_data);
    return log_error_and_queue_response_task(
        "kallsyms_symbols_state", STATE_KALLSYMS_SYMBOLS, VMI_OP_FAILURE,
        "STATE_KALLSYMS_SYMBOLS: kallsyms_num_syms read failed or zero");
  }

  // Prefer relative mode if available, else fall back to absolute addresses.
  bool use_relative = false;
  addr_t a_offsets = 0, a_relbase_sym = 0, a_addrs = 0;
  if (vmi_translate_ksym2v(vmi, "kallsyms_offsets", &a_offsets) ==
          VMI_SUCCESS &&
      vmi_translate_ksym2v(vmi, "kallsyms_relative_base", &a_relbase_sym) ==
          VMI_SUCCESS) {
    use_relative = true;
    log_info(
        "STATE_KALLSYMS_SYMBOLS: Using kallsyms_offsets + "
        "kallsyms_relative_base mode.");
  } else {
    if (vmi_translate_ksym2v(vmi, "kallsyms_addresses", &a_addrs) !=
        VMI_SUCCESS) {
      kallsyms_symbols_state_data_free(symbols_data);
      return log_error_and_queue_response_task(
          "kallsyms_symbols_state", STATE_KALLSYMS_SYMBOLS, VMI_OP_FAILURE,
          "STATE_KALLSYMS_SYMBOLS: No callable address array found (neither "
          "relative nor absolute)");
    }
    log_info(
        "STATE_KALLSYMS_SYMBOLS: Using kallsyms_addresses (absolute) mode.");
  }

  // Read token_index[256] (u16 each) for decompression.
  uint16_t token_index[TOKEN_TABLE_SIZE];
  if (!read_token_index(vmi, a_tidx, token_index)) {
    kallsyms_symbols_state_data_free(symbols_data);
    return log_error_and_queue_response_task(
        "kallsyms_symbols_state", STATE_KALLSYMS_SYMBOLS, VMI_OP_FAILURE,
        "STATE_KALLSYMS_SYMBOLS: Failed to read token_index");
  }

  addr_t ktext_s = 0, ktext_e = 0;
  if (get_kernel_text_section_range(vmi, &ktext_s, &ktext_e) != VMI_SUCCESS) {
    log_warn(
        "STATE_KALLSYMS_SYMBOLS: Failed to get kernel .text section "
        "boundaries.");
    ktext_s = ktext_e = 0;
  } else {
    log_info("STATE_KALLSYMS_SYMBOLS: Kernel .text range: [0x%" PRIx64
             ", 0x%" PRIx64 "]",
             (uint64_t)ktext_s, (uint64_t)ktext_e);
  }

  // If relative mode, fetch the live base pointer value from kallsyms_relative_base.
  // Note: On 64-bit kernels (CONFIG_KALLSYMS_BASE_RELATIVE=y),
  // storing every 64-bit address in kallsyms_addresses would cost 8 × num_syms
  // bytes in kernel memory. With ~300k symbols this is several megabytes.
  uint64_t relbase64 = 0;
  if (use_relative) {
    if (is_64) {
      if (vmi_read_64_va(vmi, a_relbase_sym, 0, &relbase64) != VMI_SUCCESS) {
        kallsyms_symbols_state_data_free(symbols_data);
        return log_error_and_queue_response_task(
            "kallsyms_symbols_state", STATE_KALLSYMS_SYMBOLS, VMI_OP_FAILURE,
            "STATE_KALLSYMS_SYMBOLS: Failed to read kallsyms_relative_base "
            "(64-bit)");
      }
    } else {
      uint32_t base32 = 0;
      if (vmi_read_32_va(vmi, a_relbase_sym, 0, &base32) != VMI_SUCCESS) {
        kallsyms_symbols_state_data_free(symbols_data);
        return log_error_and_queue_response_task(
            "kallsyms_symbols_state", STATE_KALLSYMS_SYMBOLS, VMI_OP_FAILURE,
            "STATE_KALLSYMS_SYMBOLS: Failed to read kallsyms_relative_base "
            "(32-bit)");
      }
      relbase64 = base32;
    }
  }

  // Statistics to relatively match the Clueless-Admin's framework output.
  uint32_t total = 0, reachable = 0, zero_addr = 0, name_fail = 0,
           addr_fail = 0;
  uint32_t in_text = 0, outside_text = 0;
  const bool have_text = (ktext_s && ktext_e && ktext_e > ktext_s);

  // Iterate all symbols.
  addr_t names_cursor = a_names;
  char name_buf[KSYM_MAX_NAME];
  const uint32_t log_sample = 12;
  uint32_t logged = 0;

  for (uint32_t i = 0; i < num_syms; i++) {
    // Decompress symbol name
    if (!decompress_symbol_name(vmi, token_index, names_cursor, a_ttab,
                                name_buf, sizeof(name_buf), &names_cursor)) {
      name_fail++;
      continue;
    }

    // Resolve symbol address
    addr_t virt_addr = 0;
    if (!resolve_symbol_address(vmi, i, use_relative, is_64, relbase64,
                                a_offsets, a_addrs, &virt_addr)) {
      addr_fail++;
      continue;
    }

    total++;
    if (virt_addr == 0) {
      zero_addr++;
    }

    // Optional classification.
    if (have_text) {
      if (virt_addr >= ktext_s && virt_addr <= ktext_e) {
        in_text++;
      } else {
        outside_text++;
      }
    }

    // Reachability probe: single safe byte read.
    uint8_t tmp = 0;
    if (vmi_read_8_va(vmi, virt_addr, 0, &tmp) == VMI_SUCCESS) {
      reachable++;
    }

    // Convert address to hex string
    char addr_str[32];
    (void)snprintf(addr_str, sizeof(addr_str), "0x%" PRIx64,
                   (uint64_t)virt_addr);

    // Determine symbol type (simplified - would need more sophisticated detection)
    const char* type_str = "T";  // Default to text symbol

    // Add symbol to data structure
    kallsyms_symbols_state_add_symbol(symbols_data, addr_str, type_str,
                                      name_buf, NULL);

    // Log a small sample for inspection.
    if (logged < log_sample) {
      log_debug("STATE_KALLSYMS_SYMBOLS: kallsyms[%u]: 0x%" PRIx64 "  %s%s%s",
                i, (uint64_t)virt_addr, name_buf,
                (have_text && virt_addr >= ktext_s && virt_addr <= ktext_e)
                    ? "  [.text]"
                    : "",
                (vmi_read_8_va(vmi, virt_addr, 0, &tmp) == VMI_SUCCESS)
                    ? "  [reachable]"
                    : "");
      logged++;
    }
  }

  kallsyms_symbols_state_set_summary(symbols_data, total, total, -1, NULL, NULL,
                                     -1, reachable, zero_addr, name_fail,
                                     addr_fail, in_text, outside_text);

  log_info(
      "STATE_KALLSYMS_SYMBOLS: kallsyms summary: total=%u, reachable=%u, "
      "zero=%u, "
      "name_fail=%u, addr_fail=%u, in_text=%u, outside_text=%u",
      total, reachable, zero_addr, name_fail, addr_fail, in_text, outside_text);

  if (name_fail || addr_fail) {
    log_warn(
        "STATE_KALLSYMS_SYMBOLS: kallsyms anomalies: name_fail=%u, "
        "addr_fail=%u "
        "(possible profile mismatch or memory tampering).",
        name_fail, addr_fail);
  }
  if (zero_addr) {
    log_warn("STATE_KALLSYMS_SYMBOLS: %u symbol(s) reported VA=0 (unexpected).",
             zero_addr);
  }
  if (total != num_syms) {
    log_warn(
        "STATE_KALLSYMS_SYMBOLS: Enumerated %u of %u entries (incomplete).",
        total, num_syms);
  }

  log_info("STATE_KALLSYMS_SYMBOLS callback completed.");
  return log_success_and_queue_response_task(
      "kallsyms_symbols_state", STATE_KALLSYMS_SYMBOLS, symbols_data,
      (void (*)(void*))kallsyms_symbols_state_data_free);
}
