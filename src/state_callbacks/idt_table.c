#include "state_callbacks/idt_table.h"

#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
/**
 * @brief Parse a decimal unsigned integer in the range [0, 255] from the start of a string.
 *
 * The function consumes leading ASCII whitespace, then parses consecutive decimal digits.
 * It stops at the first non-digit and writes that position to @p *endptr (never NULL).
 *
 * @param[in]  str        Input C-string (must be non-NULL).
 * @param[out] out_value  Parsed value on success.
 * @param[out] endptr     Pointer to the first unconsumed character in @p str.
 * @return true if a valid integer in [0,255] was parsed; false otherwise.
 */
static bool parse_uint8_dec(const char* str, uint8_t* out_value,
                            const char** endptr) {
  if (!str || !out_value || !endptr)
    return false;

  // Skip leading ASCII whitespace.
  const char* cursor = str;
  while (g_ascii_isspace(*cursor))
    cursor++;

  // Must start with a digit.
  if (!g_ascii_isdigit(*cursor)) {
    *endptr = cursor;
    return false;
  }

  unsigned int accumulator = 0;
  while (g_ascii_isdigit(*cursor)) {
    unsigned int digit = (unsigned int)(*cursor - '0');
    // Enforce upper bound 255.
    if (accumulator > 25U || (accumulator == 25U && digit > 5U)) {
      *endptr = cursor;
      return false;
    }
    accumulator = accumulator * 10U + digit;
    cursor++;
  }

  *out_value = (uint8_t)accumulator;
  *endptr = cursor;
  return true;
}

/**
 * @brief Load interrupt vector names (0..255) from a text file.
 *
 * The file format is line-based. Each relevant line starts with a decimal index [0..255],
 * followed by optional whitespace and a single-name token (no spaces). Lines may be blank
 * or start with '#', which are ignored. If no valid name token is present, the vector
 * remains "unknown".
 *
 * Example lines:
 * @code
 * 14   page_fault
 * 32   irq0
 * # comment
 * @endcode
 *
 * @param[in] path  Filesystem path to the index file.
 * @return A GPtrArray* of length 256 with gchar* names (owned by the array). Defaults to "unknown".
 */

static GPtrArray* load_interrupt_index_table(const char* path) {
  log_info("Loading interrupt index table from: %s", path ? path : "(null)");

  GPtrArray* table = g_ptr_array_new_with_free_func(g_free);
  g_ptr_array_set_size(table, 256);
  for (guint i = 0; i < 256; i++) {
    g_ptr_array_index(table, i) = g_strdup("unknown");
  }

  FILE* file = fopen(path, "r");
  if (!file) {
    log_warn(
        "Failed to open interrupt index file: %s. Proceeding with defaults.",
        path ? path : "(null)");
    log_info(
        "Interrupt index table initialized with all entries as 'unknown'.");
    return table;
  }

  char line[512];
  unsigned long lineno = 0;
  unsigned int names_set = 0;

  while (fgets(line, sizeof(line), file)) {
    lineno++;

    // Trim leading whitespace
    char* line_cursor = line;
    while (g_ascii_isspace(*line_cursor))
      line_cursor++;
    if (*line_cursor == '\0' || *line_cursor == '#')
      continue;  // skip blank/comment lines

    uint8_t idx8 = 0;
    const char* after_idx = NULL;
    if (!parse_uint8_dec(line_cursor, &idx8, &after_idx)) {
      continue;  // Not a valid index; ignore line
    }

    // Skip whitespace after index
    while (g_ascii_isspace(*after_idx))
      after_idx++;

    // Optionally, capture the next token as the name; stop at whitespace or '#'
    if (*after_idx == '\0' || *after_idx == '#') {
      continue;  // No name provided; leave as "unknown"
    }

    const char* name_start = after_idx;
    const char* name_end = name_start;
    while (*name_end && !g_ascii_isspace(*name_end) && *name_end != '#')
      name_end++;

    if (name_end > name_start) {
      gchar* name = g_strndup(name_start, (gsize)(name_end - name_start));
      // Replace entry
      g_free(g_ptr_array_index(table, (guint)idx8));
      g_ptr_array_index(table, (guint)idx8) = name;
      log_info("Interrupt index loaded: vector=%u name=%s", (unsigned)idx8,
               name);
      names_set++;
    }
  }

  if (ferror(file)) {
    log_warn(
        "I/O error while reading %s at line %lu; keeping parsed entries so "
        "far.",
        path, lineno);
  }

  (void)fclose(file);
  log_info(
      "Completed loading interrupt index table: %u entries named, %u unknown.",
      names_set, 256U - names_set);

  return table;
}

/**
 * @brief Read a 64-bit handler address from an IA-32e (x86_64) 16-byte IDT gate.
 *
 * Layout: offset_low[0:1], selector[2:3], ist[4], type[5], offset_mid[6:7], offset_high[8:11], zero[12:15].
 *
 * @param vmi       LibVMI instance.
 * @param idt_base  Virtual address of IDT base.
 * @param vector    Interrupt vector (0..255).
 * @param out       Output: resolved handler address.
 * @return true on success; false on read failure.
 */
static bool read_idt_entry_addr_ia32e(vmi_instance_t vmi, addr_t idt_base,
                                      uint16_t vector, addr_t* out) {
  if (!out)
    return false;

  uint16_t off_low = 0, off_mid = 0;
  uint32_t off_high = 0;

  if (vmi_read_16_va(vmi, idt_base + (addr_t)vector * 16 + 0, 0, &off_low) !=
      VMI_SUCCESS)
    return false;
  if (vmi_read_16_va(vmi, idt_base + (addr_t)vector * 16 + 6, 0, &off_mid) !=
      VMI_SUCCESS)
    return false;
  if (vmi_read_32_va(vmi, idt_base + (addr_t)vector * 16 + 8, 0, &off_high) !=
      VMI_SUCCESS)
    return false;

  *out = (((addr_t)off_high) << 32) | (((addr_t)off_mid) << 16) |
         ((addr_t)off_low);
  return true;
}

/**
 * @brief Read a 32-bit handler address from an IA-32 (x86) 8-byte IDT gate.
 *
 * Layout: offset_low[0:1], selector[2:3], count[4], type[5], offset_high[6:7].
 *
 * @param vmi       LibVMI instance.
 * @param idt_base  Virtual address of IDT base.
 * @param vector    Interrupt vector (0..255).
 * @param out       Output: resolved handler address.
 * @return true on success; false on read failure.
 */
static bool read_idt_entry_addr_ia32(vmi_instance_t vmi, addr_t idt_base,
                                     uint16_t vector, addr_t* out) {
  if (!out)
    return false;

  uint16_t off_low = 0, off_high = 0;

  if (vmi_read_16_va(vmi, idt_base + (addr_t)vector * 8 + 0, 0, &off_low) !=
      VMI_SUCCESS)
    return false;
  if (vmi_read_16_va(vmi, idt_base + (addr_t)vector * 8 + 6, 0, &off_high) !=
      VMI_SUCCESS)
    return false;

  *out = (((addr_t)off_high) << 16) | ((addr_t)off_low);
  return true;
}

// NOLINTNEXTLINE
uint32_t state_idt_table_callback(vmi_instance_t vmi, void* context) {
  (void)context;

  log_info("Executing STATE_IDT_TABLE callback.");

  // Resolve kernel text bounds
  addr_t kernel_start = 0, kernel_end = 0;
  if (vmi_translate_ksym2v(vmi, "_stext", &kernel_start) != VMI_SUCCESS) {
    log_error("Failed to resolve kernel symbol '_stext'.");
    return VMI_FAILURE;
  }
  if (vmi_translate_ksym2v(vmi, "_etext", &kernel_end) != VMI_SUCCESS) {
    log_error("Failed to resolve kernel symbol '_etext'.");
    return VMI_FAILURE;
  }
  if (kernel_end <= kernel_start) {
    log_warn("Kernel text bounds appear invalid: _stext=0x%" PRIx64
             ", _etext=0x%" PRIx64,
             (uint64_t)kernel_start, (uint64_t)kernel_end);
  }

  log_info("Kernel text range: [0x%" PRIx64 ", 0x%" PRIx64 "]",
           (uint64_t)kernel_start, (uint64_t)kernel_end);

  // Read IDTR base from vCPU 0 (adjust if you carry per-vCPU context)
  addr_t idt_base = 0;
  if (vmi_get_vcpureg(vmi, &idt_base, IDTR_BASE, 0) != VMI_SUCCESS) {
    log_error("Failed to read IDTR base from vCPU 0.");
    return VMI_FAILURE;
  }

  log_info("IDTR base (vCPU 0): 0x%" PRIx64, (uint64_t)idt_base);

  // Load vector names (never NULL; defaults to "unknown")
  GPtrArray* vec_names = load_interrupt_index_table(INTERRUPT_INDEX_FILE);
  if (!vec_names || vec_names->len != 256) {
    // Highly unexpected, but guard anyway
    log_warn(
        "Interrupt index table not fully initialized; proceeding with "
        "best-effort.");
  }

  const bool ia32e = (vmi_get_page_mode(vmi, 0) == VMI_PM_IA32E);
  const uint16_t gate_size = ia32e ? 16 : 8;
  const uint16_t max_vectors = 256;

  log_info("Page mode: %s; gate size: %u; scanning %u vectors.",
           ia32e ? "IA-32e (x86_64)" : "IA-32 (x86)", gate_size, max_vectors);

  int hooked = 0;
  for (uint16_t vec = 0; vec < max_vectors; vec++) {
    addr_t handler = 0;
    const bool result =
        ia32e ? read_idt_entry_addr_ia32e(vmi, idt_base, vec, &handler)
              : read_idt_entry_addr_ia32(vmi, idt_base, vec, &handler);

    if (!result) {
      log_warn("Failed to read IDT entry %u at 0x%" PRIx64, vec,
               (uint64_t)(idt_base + (addr_t)vec * gate_size));
      continue;
    }

    const char* name = (vec_names && vec < vec_names->len)
                           ? (const char*)g_ptr_array_index(vec_names, vec)
                           : "unknown";
    if (!name)
      name = "unknown";

    if (strcmp(name, "unknown") != 0) {
      log_info("Vector %u (%s) handler at 0x%" PRIx64, vec, name,
               (uint64_t)handler);
    }

    // Only report named (non-"unknown") vectors
    if (strcmp(name, "unknown") != 0) {
      const bool outside_text =
          (handler < kernel_start) || (handler > kernel_end);
      if (outside_text) {
        log_info(
            "Interrupt handler %s (vector %u) address changed to 0x%" PRIx64,
            name, vec, (uint64_t)handler);
        hooked++;
      }
    }
  }

  if (hooked == 0) {
    log_info("No unexpected interrupt handler addresses detected.");
  } else {
    log_info("Total interrupt handlers flagged: %d", hooked);
  }

  if (vec_names)
    g_ptr_array_free(vec_names, TRUE);
  log_info("STATE_IDT_TABLE callback completed.");
  return VMI_SUCCESS;
}
