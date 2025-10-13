#include "utils.h"

#include <arpa/inet.h>
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

/**
 * @brief Log success and queue a success response for an event.
 *
 * @param event_name Name of the event for logging purposes.
 * @param event_type Type of event that succeeded.
 * @param data_ptr Pointer to the event data to include in response.
 * @param data_free_func Function to free the data_ptr when done.
 * @return VMI_EVENT_RESPONSE_NONE on success, VMI_EVENT_INVALID on failure.
 */
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

void free_string_index(char** array, size_t count) {
  if (!array) {
    return;
  }
  for (size_t i = 0; i < count; i++) {
    g_free(array[i]);
  }
  g_free(array);
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
      (void)fclose(file);
      free_string_index(names, count);
      return NULL;
    }

    // Reallocate array
    char** temp = g_realloc(names, sizeof(char*) * (count + 1));
    if (!temp) {
      log_error("Failed to reallocate names array");
      g_free(name);
      (void)fclose(file);
      free_string_index(names, count);
      return NULL;
    }

    names = temp;
    names[count] = name;
    count++;
  }

  (void)fclose(file);
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

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
bool ipv4_is_public(uint32_t ip_be) {
  uint32_t ip_addr = ntohl(ip_be);

#define IN(ip_addr_, base_, maskbits_)                              \
  (((ip_addr_) &                                                    \
    ((maskbits_) == 0 ? 0u : 0xFFFFFFFFu << (32 - (maskbits_)))) == \
   ((base_) & ((maskbits_) == 0 ? 0u : 0xFFFFFFFFu << (32 - (maskbits_)))))

  // 0.0.0.0/8
  if (IN(ip_addr, 0x00000000U, 8))
    return false;
  // 10.0.0.0/8 - Private (RFC 1918)
  if (IN(ip_addr, 0x0A000000U, 8))
    return false;
  // 100.64.0.0/10 - Shared Address Space (RFC 6598)
  if (IN(ip_addr, 0x64400000U, 10))
    return false;
  // 127.0.0.0/8 - Loopback (RFC 1122)
  if (IN(ip_addr, 0x7F000000U, 8))
    return false;
  // 169.254.0.0/16 - Link-Local (RFC 3927)
  if (IN(ip_addr, 0xA9FE0000U, 16))
    return false;
  // 172.16.0.0/12 - Private (RFC 1918)
  if (IN(ip_addr, 0xAC100000U, 12))
    return false;
  // 192.0.0.0/24 - IETF Protocol Assignments
  if (IN(ip_addr, 0xC0000000U, 24))
    return false;
  // 192.0.2.0/24 - Documentation TEST-NET-1 (RFC 5737)
  if (IN(ip_addr, 0xC0000200U, 24))
    return false;
  // 192.88.99.0/24 - 6to4 Relay Anycast (RFC 7526)
  if (IN(ip_addr, 0xC0586300U, 24))
    return false;
  // 192.168.0.0/16 - Private (RFC 1918)
  if (IN(ip_addr, 0xC0A80000U, 16))
    return false;
  // 198.18.0.0/15 - Benchmarking (RFC 2544)
  if (IN(ip_addr, 0xC6120000U, 15))
    return false;
  // 198.51.100.0/24 - Documentation TEST-NET-2 (RFC 5737)
  if (IN(ip_addr, 0xC6336400U, 24))
    return false;
  // 203.0.113.0/24 - Documentation TEST-NET-3 (RFC 5737)
  if (IN(ip_addr, 0xCB007100U, 24))
    return false;
  // 224.0.0.0/4 - Multicast (RFC 5771)
  if (IN(ip_addr, 0xE0000000U, 4))
    return false;
  // 240.0.0.0/4 - Reserved/Future use
  if (IN(ip_addr, 0xF0000000U, 4))
    return false;

  return true;

#undef IN
}

bool is_suspicious_port(uint16_t port) {
  // Common rootkit/backdoor ports
  static const uint16_t suspicious_ports[] = {
      666,   667,   // Reptile rootkit
      4444,  5555,  // Common backdoor ports
      31337,        // Back Orifice (LEET)
      5900,         // VNC Rooty
      8000,         // Web backdoors
      0,     65535  // Invalid ports
  };

  for (size_t i = 0; i < sizeof(suspicious_ports) / sizeof(suspicious_ports[0]);
       i++) {
    if (port == suspicious_ports[i]) {
      return true;
    }
  }

  // High ports
  return (port >= 60000);
}

const char* get_port_classification(uint16_t port) {
  if (port < 1024)
    return "privileged";
  if (port < 49152)
    return "registered";
  return "dynamic";
}

const char* get_ip_type_string(uint32_t ip_addr) {
  if (ip_addr == 0)
    return "ANY";
  if (ip_addr == 0x7F000001)
    return "localhost";
  if ((ip_addr & 0xFF000000) == 0x0A000000)
    return "private";
  if ((ip_addr & 0xFFF00000) == 0xAC100000)
    return "private";
  if ((ip_addr & 0xFFFF0000) == 0xC0A80000)
    return "private";

  // Use comprehensive check for public
  if (ipv4_is_public(htonl(ip_addr)))
    return "public";

  return "special";
}

status_t get_standard_registers(vmi_instance_t vmi, uint32_t vcpu_id,
                                uint64_t* rip, uint64_t* cr3, uint64_t* rsp) {
  if (!vmi || !rip || !cr3 || !rsp) {
    return VMI_FAILURE;
  }

  if (vmi_get_vcpureg(vmi, rip, RIP, vcpu_id) != VMI_SUCCESS) {
    return VMI_FAILURE;
  }

  if (vmi_get_vcpureg(vmi, cr3, CR3, vcpu_id) != VMI_SUCCESS) {
    return VMI_FAILURE;
  }

  if (vmi_get_vcpureg(vmi, rsp, RSP, vcpu_id) != VMI_SUCCESS) {
    return VMI_FAILURE;
  }

  return VMI_SUCCESS;
}
