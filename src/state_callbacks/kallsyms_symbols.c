#include "state_callbacks/kallsyms_symbols.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "event_handler.h"
#include "utils.h"

#define KSYM_MAX_NAME 1024  // Max symbol name length.

// NOLINTNEXTLINE
uint32_t state_kallsyms_symbols_callback(vmi_instance_t vmi, void* context) {
  // Preconditions
  if (!vmi || !context) {
    log_error(
        "STATE_KALLSYMS_SYMBOLS: Invalid arguments to kallsyms symbols state "
        "callback.");
    return VMI_FAILURE;
  }

  event_handler_t* event_handler = (event_handler_t*)context;
  if (!event_handler || !event_handler->is_paused) {
    log_error(
        "STATE_KALLSYMS_SYMBOLS: Callback requires a paused VM instance.");
    return VMI_FAILURE;
  }

  log_info("Executing STATE_KALLSYMS_SYMBOLS callback.");

  // Detect guest pointer width.
  const bool is_64 = (vmi_get_page_mode(vmi, 0) == VMI_PM_IA32E);

  addr_t a_num = 0, a_names = 0, a_ttab = 0, a_tidx = 0;
  if (vmi_translate_ksym2v(vmi, "kallsyms_num_syms", &a_num) != VMI_SUCCESS ||
      vmi_translate_ksym2v(vmi, "kallsyms_names", &a_names) != VMI_SUCCESS ||
      vmi_translate_ksym2v(vmi, "kallsyms_token_table", &a_ttab) !=
          VMI_SUCCESS ||
      vmi_translate_ksym2v(vmi, "kallsyms_token_index", &a_tidx) !=
          VMI_SUCCESS) {
    log_error("Failed to resolve one or more kallsyms arrays.");
    return VMI_FAILURE;
  }

  uint32_t num_syms = 0;
  if (vmi_read_32_va(vmi, a_num, 0, &num_syms) != VMI_SUCCESS ||
      num_syms == 0) {
    log_error("kallsyms_num_syms read failed or zero.");
    return VMI_FAILURE;
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
      log_error(
          "STATE_KALLSYMS_SYMBOLS: No callable address array found (neither "
          "relative nor absolute).");
      return VMI_FAILURE;
    }
    log_info(
        "STATE_KALLSYMS_SYMBOLS: Using kallsyms_addresses (absolute) mode.");
  }

  // Read token_index[256] (u16 each) for decompression.
  uint16_t token_index[256];
  for (int i = 0; i < 256; i++) {
    if (vmi_read_16_va(vmi, a_tidx + (addr_t)(i * 2), 0, &token_index[i]) !=
        VMI_SUCCESS) {
      log_error("STATE_KALLSYMS_SYMBOLS: Failed to read token_index[%d].", i);
      return VMI_FAILURE;
    }
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
        log_error(
            "STATE_KALLSYMS_SYMBOLS: Failed to read kallsyms_relative_base "
            "(64-bit).");
        return VMI_FAILURE;
      }
    } else {
      uint32_t base32 = 0;
      if (vmi_read_32_va(vmi, a_relbase_sym, 0, &base32) != VMI_SUCCESS) {
        log_error(
            "STATE_KALLSYMS_SYMBOLS: Failed to read kallsyms_relative_base "
            "(32-bit).");
        return VMI_FAILURE;
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
    uint8_t comp_len = 0;
    if (vmi_read_8_va(vmi, names_cursor, 0, &comp_len) != VMI_SUCCESS) {
      name_fail++;
      names_cursor += 1;
      continue;
    }
    addr_t comp_codes = names_cursor + 1;

    size_t out_used = 0;
    bool name_ok = true;

    for (uint32_t k = 0; k < comp_len && name_ok; k++) {
      uint8_t code = 0;
      if (vmi_read_8_va(vmi, comp_codes + k, 0, &code) != VMI_SUCCESS) {
        name_ok = false;
        break;
      }
      // Expand token => append chars from token_table until NULL.
      uint16_t off = token_index[code];
      addr_t tcur = a_ttab + (addr_t)off;
      for (;;) {
        uint8_t ch = 0;
        if (vmi_read_8_va(vmi, tcur++, 0, &ch) != VMI_SUCCESS) {
          name_ok = false;
          break;
        }
        if (ch == 0)
          break;
        if (out_used + 1 >= sizeof(name_buf)) {
          name_ok = false;
          break;
        }
        name_buf[out_used++] = (char)ch;
      }
    }

    if (!name_ok) {
      name_fail++;
      // Advance cursor to next entry (best effort).
      names_cursor = comp_codes + comp_len;
      continue;
    }

    name_buf[out_used] = '\0';
    names_cursor = comp_codes + comp_len;

    // --- Resolve address entry i.
    addr_t va = 0;
    if (use_relative) {
      uint32_t rel_u32 = 0;
      if (vmi_read_32_va(vmi, a_offsets + (addr_t)(i * 4), 0, &rel_u32) !=
          VMI_SUCCESS) {
        addr_fail++;
        continue;
      }
      int32_t rel = (int32_t)rel_u32;  // signed add
      va = (addr_t)((uint64_t)relbase64 + (int64_t)rel);
    } else {
      if (is_64) {
        uint64_t a64 = 0;
        if (vmi_read_64_va(vmi, a_addrs + (addr_t)(i * 8), 0, &a64) !=
            VMI_SUCCESS) {
          addr_fail++;
          continue;
        }
        va = (addr_t)a64;
      } else {
        uint32_t a32 = 0;
        if (vmi_read_32_va(vmi, a_addrs + (addr_t)(i * 4), 0, &a32) !=
            VMI_SUCCESS) {
          addr_fail++;
          continue;
        }
        va = (addr_t)a32;
      }
    }

    total++;
    if (va == 0)
      zero_addr++;

    // Optional classification.
    if (have_text) {
      if (va >= ktext_s && va <= ktext_e)
        in_text++;
      else
        outside_text++;
    }

    // Reachability probe: single safe byte read.
    uint8_t tmp = 0;
    if (vmi_read_8_va(vmi, va, 0, &tmp) == VMI_SUCCESS)
      reachable++;

    // Log a small sample for inspection.
    if (logged < log_sample) {
      log_info("STATE_KALLSYMS_SYMBOLS: kallsyms[%u]: 0x%" PRIx64 "  %s%s%s", i,
               (uint64_t)va, name_buf,
               (have_text && va >= ktext_s && va <= ktext_e) ? "  [.text]" : "",
               (vmi_read_8_va(vmi, va, 0, &tmp) == VMI_SUCCESS)
                   ? "  [reachable]"
                   : "");
      logged++;
    }
  }

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
  return VMI_SUCCESS;
}
