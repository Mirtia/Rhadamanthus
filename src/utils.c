#include "utils.h"

#include <glib.h>
#include <inttypes.h>
#include <log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

event_response_t log_error_and_queue_response_event(const char* event_name,
                                                    event_task_id_t event_type,
                                                    int error_code,
                                                    const char* message) {
  log_error("%s", message);

  if (json_serializer_is_global_initialized()) {
    struct response* error_resp = create_error_response(
        EVENT, (void*)(uintptr_t)event_type, error_code, message);
    if (error_resp) {
      json_serializer_queue_global(event_name, error_resp);
    }
  }
  return VMI_EVENT_INVALID;
}

int log_error_and_queue_response_task(const char* task_name,
                                      state_task_id_t task_type, int error_code,
                                      const char* message) {
  log_error("%s", message);

  if (json_serializer_is_global_initialized()) {
    struct response* error_resp = create_error_response(
        EVENT, (void*)(uintptr_t)task_type, error_code, message);
    if (error_resp) {
      json_serializer_queue_global(task_name, error_resp);
    }
  }
  return VMI_FAILURE;
}

event_response_t log_error_and_queue_response_interrupt(
    const char* interrupt_name, interrupt_task_id_t interrupt_type,
    int error_code, const char* message) {
  log_error("%s", message);

  if (json_serializer_is_global_initialized()) {
    struct response* error_resp = create_error_response(
        INTERRUPT, (void*)(uintptr_t)interrupt_type, error_code, message);
    if (error_resp) {
      json_serializer_queue_global(interrupt_name, error_resp);
    }
  }
  return VMI_EVENT_INVALID;
}

event_response_t log_success_and_queue_response_event(
    const char* event_name, event_task_id_t event_type, void* data_ptr,
    void (*data_free_func)(void*)) {
  if (json_serializer_is_global_initialized()) {
    struct response* success_resp = create_success_response(
        EVENT, (void*)(uintptr_t)event_type, data_ptr, data_free_func);
    if (success_resp) {
      json_serializer_queue_global(event_name, success_resp);
      return VMI_EVENT_RESPONSE_NONE;
    }
    log_error("Failed to create success response for %s event.", event_name);
    if (data_free_func && data_ptr) {
      data_free_func(data_ptr);
    }
    return VMI_EVENT_INVALID;
  }

  if (data_free_func && data_ptr) {
    data_free_func(data_ptr);
  }
  return VMI_EVENT_RESPONSE_NONE;
}

event_response_t log_success_and_queue_response_interrupt(
    const char* interrupt_name, interrupt_task_id_t interrupt_type,
    void* data_ptr, void (*data_free_func)(void*)) {

  if (json_serializer_is_global_initialized()) {
    struct response* success_resp = create_success_response(
        INTERRUPT, (void*)(uintptr_t)interrupt_type, data_ptr, data_free_func);
    if (success_resp) {
      json_serializer_queue_global(interrupt_name, success_resp);
      return VMI_EVENT_RESPONSE_NONE;
    }
    log_error("Failed to create success response for %s event.",
              interrupt_name);
    if (data_free_func && data_ptr) {
      data_free_func(data_ptr);
    }
    return VMI_EVENT_INVALID;
  }

  if (data_free_func && data_ptr) {
    data_free_func(data_ptr);
  }
  return VMI_EVENT_RESPONSE_NONE;
}

int log_success_and_queue_response_task(const char* task_name,
                                        state_task_id_t task_type,
                                        void* data_ptr,
                                        void (*data_free_func)(void*)) {
  if (json_serializer_is_global_initialized()) {
    struct response* success_resp = create_success_response(
        STATE, (void*)(uintptr_t)task_type, data_ptr, data_free_func);
    if (success_resp) {
      json_serializer_queue_global(task_name, success_resp);
      return VMI_SUCCESS;
    }
    log_error("Failed to create success response for %s task.", task_name);
    if (data_free_func && data_ptr) {
      data_free_func(data_ptr);
    }
    return VMI_FAILURE;
  }

  if (data_free_func && data_ptr) {
    data_free_func(data_ptr);
  }
  return VMI_SUCCESS;
}

uint32_t get_kernel_text_section_range(vmi_instance_t vmi, addr_t* start_addr,
                                       addr_t* end_addr) {
  if (!vmi) {
    log_debug("VMI instance is uninitialized.");
    return VMI_FAILURE;
  }

  if ((vmi_translate_ksym2v(vmi, "_stext", start_addr) == VMI_FAILURE ||
       vmi_translate_ksym2v(vmi, "_etext", end_addr) == VMI_FAILURE)) {
    log_debug("Failed to resolve kernel .text boundaries.");
    return VMI_FAILURE;
  }

  return VMI_SUCCESS;
}

bool is_in_kernel_text(vmi_instance_t vmi, addr_t addr) {

  if (!vmi) {
    log_debug("VMI instance is uninitialized.");
    return false;
  }

  addr_t start_addr = 0, end_addr = 0;

  if (get_kernel_text_section_range(vmi, &start_addr, &end_addr) !=
      VMI_SUCCESS) {
    log_debug("Unable to get kernel text section range for address check.");
    return false;
  }
  // Kernel bounds: [start_addr, end_addr)
  return (addr >= start_addr && addr < end_addr);
}

void log_vcpu_state(vmi_instance_t vmi, uint32_t vcpu_id, addr_t kaddr,
                    const char* context) {
  if (!vmi) {
    log_warn("log_vcpu_state: Invalid VMI instance");
    return;
  }

  reg_t rip = 0, rflags = 0;
  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    log_warn("log_vcpu_state: Failed to get RIP for vCPU %u", vcpu_id);
    rip = 0;
  }

  if (vmi_get_vcpureg(vmi, &rflags, RFLAGS, vcpu_id) != VMI_SUCCESS) {
    log_warn("log_vcpu_state: Failed to get RFLAGS for vCPU %u", vcpu_id);
    rflags = 0;
  }

  uint8_t byte_at_kaddr = 0;
  if (kaddr != 0) {
    if (vmi_read_8_va(vmi, kaddr, 0, &byte_at_kaddr) != VMI_SUCCESS) {
      log_warn("log_vcpu_state: Failed to read byte at 0x%" PRIx64, kaddr);
      // Sentinel value.
      byte_at_kaddr = 0xFF;
    }

    unsigned int tf_flag = (unsigned int)((rflags >> 8) & 1);

    if (kaddr != 0) {
      log_info("%s state: RIP=0x%" PRIx64 " TF=%u byte@0x%" PRIx64
               "=0x%02x vCPU=%u",
               context ? context : "VCPU", (uint64_t)rip, tf_flag, kaddr,
               byte_at_kaddr, vcpu_id);
    } else {
      log_info("%s state: RIP=0x%" PRIx64 " TF=%u vCPU=%u",
               context ? context : "VCPU", (uint64_t)rip, tf_flag, vcpu_id);
    }
  }
}

void cjson_add_hex_u32(cJSON* parent, const char* key, uint32_t val) {
  char buf[2 + 8 + 1];  // "0x" + 8 hex digits + NUL
  (void)snprintf(buf, sizeof(buf), "0x%08" PRIx32, val);
  cJSON_AddStringToObject(parent, key, buf);
}

void cjson_add_hex_u64(cJSON* parent, const char* key, uint64_t val) {
  char buffer[20];
  (void)snprintf(buffer, sizeof(buffer), "0x%016" PRIx64, val);
  cJSON_AddStringToObject(parent, key, buffer);
}

void cjson_add_hex_addr(cJSON* parent, const char* key, addr_t val) {
  char buffer[20];
  (void)snprintf(buffer, sizeof(buffer), "0x%016" PRIx64, (uint64_t)val);
  cJSON_AddStringToObject(parent, key, buffer);
}

void cjson_add_bool(cJSON* parent, const char* key, bool val) {
  cJSON_AddBoolToObject(parent, key, val);
}

char** parse_index_file(const char* index_file_path, size_t* count_dst) {
  if (!index_file_path || !count_dst) {
    return NULL;
  }

  FILE* file = fopen(index_file_path, "r");
  if (!file) {
    log_error("Failed to open index file: %s", index_file_path);
    return NULL;
  }

  char** names = NULL;
  size_t count = 0;
  char line[256];

  while (fgets(line, sizeof(line), file)) {
    // Skip empty lines and comments
    if (line[0] == '\n' || line[0] == '#') {
      continue;
    }

    // Parse line: "number\tname"
    char* tab_pos = strchr(line, '\t');
    if (!tab_pos) {
      continue;  // Skip malformed lines
    }

    // Extract name (after the tab)
    char* name_start = tab_pos + 1;
    // Remove newline if present
    char* newline = strchr(name_start, '\n');
    if (newline) {
      *newline = '\0';
    }

    // Allocate space for the name
    char* name = g_strdup(name_start);
    if (!name) {
      log_error("Failed to allocate memory for name");
      fclose(file);
      // Clean up already allocated names
      for (size_t i = 0; i < count; i++) {
        g_free(names[i]);
      }
      g_free(names);
      return NULL;
    }

    // Reallocate array
    char** temp = g_realloc(names, sizeof(char*) * (count + 1));
    if (!temp) {
      log_error("Failed to reallocate names array");
      g_free(name);
      fclose(file);
      // Clean up already allocated names
      for (size_t i = 0; i < count; i++) {
        g_free(names[i]);
      }
      g_free(names);
      return NULL;
    }

    names = temp;
    names[count] = name;
    count++;
  }

  fclose(file);
  *count_dst = count;

  log_debug("Loaded %zu entries from index file: %s", count, index_file_path);
  return names;
}

char* resolve_syscall_name(uint32_t syscall_number) {
  static char** syscall_names = NULL;
  static size_t syscall_count = 0;
  static bool initialized = false;

  // Initialize syscall names from index file on first call
  if (!initialized) {
    syscall_names = parse_index_file(SYSCALL_INDEX_FILE, &syscall_count);
    if (!syscall_names) {
      log_error("Failed to load syscall index file");
      return g_strdup_printf("syscall_%u", syscall_number);
    }
    initialized = true;
  }

  // Look up the syscall name
  if (syscall_number < syscall_count && syscall_names[syscall_number]) {
    return g_strdup(syscall_names[syscall_number]);
  }

  // If not found, return a formatted string with the number
  return g_strdup_printf("syscall_%u", syscall_number);
}

char* resolve_interrupt_name(uint8_t interrupt_vector) {
  static char** interrupt_names = NULL;
  static size_t interrupt_count = 0;
  static bool initialized = false;

  // Initialize interrupt names from index file on first call
  if (!initialized) {
    interrupt_names = parse_index_file(INTERRUPT_INDEX_FILE, &interrupt_count);
    if (!interrupt_names) {
      log_error("Failed to load interrupt index file");
      return g_strdup_printf("interrupt_%u", interrupt_vector);
    }
    initialized = true;
  }

  // Look up the interrupt name
  if (interrupt_vector < interrupt_count && interrupt_names[interrupt_vector]) {
    return g_strdup(interrupt_names[interrupt_vector]);
  }

  // If not found, return a formatted string with the number
  return g_strdup_printf("interrupt_%u", interrupt_vector);
}

/**
 * @brief Parse a decimal unsigned integer in the range [0, 255] from the start of a string.
 *
 * The function consumes leading ASCII whitespace, then parses consecutive decimal digits.
 * It stops at the first non-digit and writes that position to @p *endptr (never NULL).
 *
 * @param str        Input C-string (must be non-NULL).
 * @param out_value  Parsed value on success.
 * @param endptr     Pointer to the first unconsumed character in @p str.
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

GPtrArray* load_interrupt_index_table(const char* path) {
  log_info("Loading interrupt index table from: %s.", path ? path : "(null)");

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

    while (g_ascii_isspace(*after_idx))
      after_idx++;

    // Optionally, capture the next token as the name; stop at whitespace or '#'
    // No name provided; leave as "unknown"
    if (*after_idx == '\0' || *after_idx == '#') {
      continue;
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
