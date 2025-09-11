#include "state_callbacks/syscall_table.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include "event_handler.h"
#include "state_callbacks/responses/syscall_table_response.h"
#include "utils.h"

/**
 * @brief Frees the syscall index array.
 * 
 * @param sys_index The syscall index array to clean up.  
 * @param size The number of entries in the syscall index array.
 */
static void cleanup_sys_index(char** sys_index, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    g_free(sys_index[i]);
  }
  g_free(sys_index);
}

/**
 * @brief Parses the syscall index file to extract syscall names and their indices.
 * 
 * @param count_dst Pointer to store the number of syscalls parsed.
 * @return char** An array of syscall names, or NULL on failure.
 */
static char** parse_syscall_index_file(size_t* count_dst) {
  FILE* file = fopen(SYSCALL_INDEX_FILE, "r");
  if (!file) {
    log_error("Failed to open syscall index file: %s", SYSCALL_INDEX_FILE);
    return NULL;
  }

  char** sys_index = NULL;
  size_t count = 0;
  char line[256];
  char name_buf[SYSCALL_NAME_MAX_LEN];

  while (fgets(line, sizeof(line), file)) {
    char* ptr = line;
    while (g_ascii_isspace(*ptr))
      ptr++;

    char* endptr = NULL;
    long parsed_index = strtol(ptr, &endptr, 10);
    if (endptr == ptr || parsed_index < 0 || parsed_index > INT_MAX) {
      log_debug("Invalid index in line: %s", line);
      continue;
    }

    while (g_ascii_isspace(*endptr))
      endptr++;
    if (*endptr == '\0' || *endptr == '\n') {
      log_debug("Missing name in line: %s", line);
      continue;
    }

    char* name = g_strdup(endptr);
    if (!name) {
      log_error("Endptr was NULL. Strdup failed for line: %s", line);
      (void)fclose(file);
      cleanup_sys_index(sys_index, count);
      return NULL;
    }

    name[strcspn(name, "\r\n")] = '\0';
    char** temp = g_realloc(sys_index, sizeof(char*) * (count + 1));
    if (!temp) {
      log_error("Realloc failed while expanding syscall index array.");
      g_free(name);
      (void)fclose(file);
      cleanup_sys_index(sys_index, count);
      return NULL;
    }

    sys_index = temp;
    sys_index[count++] = name;
  }

  (void)fclose(file);
  *count_dst = count;
  return sys_index;
}

uint32_t state_syscall_table_callback(vmi_instance_t vmi, void* context) {
  // Preconditions
  if (!vmi || !context) {
    return log_error_and_queue_response_task(
        "syscall_table_state", STATE_SYSCALL_TABLE, INVALID_ARGUMENTS,
        "STATE_SYSCALL_TABLE: Invalid arguments to syscall table state "
        "callback.");
  }

  event_handler_t* event_handler = (event_handler_t*)context;
  if (!event_handler || !event_handler->is_paused) {
    return log_error_and_queue_response_task(
        "syscall_table_state", STATE_SYSCALL_TABLE, INVALID_ARGUMENTS,
        "STATE_SYSCALL_TABLE: Callback requires a valid event handler "
        "context.");
  }

  log_info("Executing STATE_SYSCALL_TABLE callback.");

  // Create syscall table state data structure
  syscall_table_state_data_t* syscall_data = syscall_table_state_data_new();
  if (!syscall_data) {
    return log_error_and_queue_response_task(
        "syscall_table_state", STATE_SYSCALL_TABLE, MEMORY_ALLOCATION_FAILURE,
        "STATE_SYSCALL_TABLE: Failed to allocate memory for syscall table "
        "state data.");
  }

  // Parse syscall index file
  size_t syscall_number = 0;
  char** sys_index = parse_syscall_index_file(&syscall_number);
  if (!sys_index) {
    syscall_table_state_data_free(syscall_data);
    return log_error_and_queue_response_task(
        "syscall_table_state", STATE_SYSCALL_TABLE, VMI_OP_FAILURE,
        "STATE_SYSCALL_TABLE: Failed to parse syscall index file.");
  }

  // Resolve kernel text bounds
  addr_t kernel_start_addr = 0, kernel_end_addr = 0;
  if (get_kernel_text_section_range(vmi, &kernel_start_addr,
                                    &kernel_end_addr) != VMI_SUCCESS) {
    cleanup_sys_index(sys_index, syscall_number);
    syscall_table_state_data_free(syscall_data);
    return log_error_and_queue_response_task(
        "syscall_table_state", STATE_SYSCALL_TABLE, VMI_OP_FAILURE,
        "STATE_SYSCALL_TABLE: Failed to resolve kernel text section range.");
  }

  syscall_table_state_set_kernel_range(syscall_data, kernel_start_addr,
                                       kernel_end_addr);

  log_info("STATE_SYSCALL_TABLE: Kernel text range: [0x%" PRIx64 ", 0x%" PRIx64
           "]",
           (uint64_t)kernel_start_addr, (uint64_t)kernel_end_addr);

  // Resolve syscall table address
  addr_t sys_call_table_addr = 0;
  if (vmi_translate_ksym2v(vmi, "sys_call_table", &sys_call_table_addr) ==
      VMI_FAILURE) {
    cleanup_sys_index(sys_index, syscall_number);
    syscall_table_state_data_free(syscall_data);
    return log_error_and_queue_response_task(
        "syscall_table_state", STATE_SYSCALL_TABLE, VMI_OP_FAILURE,
        "STATE_SYSCALL_TABLE: Failed to resolve symbol sys_call_table.");
  }

  syscall_table_state_set_table_info(syscall_data, sys_call_table_addr,
                                     (uint32_t)syscall_number);

  log_info("STATE_SYSCALL_TABLE: sys_call_table address: 0x%" PRIx64,
           sys_call_table_addr);

  // Analyze each syscall
  uint32_t syscall_hit_count = 0;
  for (size_t i = 0; i < syscall_number; ++i) {
    addr_t sys_call_addr = 0;
    if (vmi_read_addr_va(vmi, sys_call_table_addr + i * sizeof(addr_t), 0,
                         &sys_call_addr) == VMI_FAILURE) {
      log_debug(
          "STATE_SYSCALL_TABLE: Failed to read syscall address at index %zu.",
          i);
      // Add syscall with unknown address
      syscall_table_state_add_syscall(syscall_data, (uint32_t)i, sys_index[i],
                                      0, false);
      continue;
    }

    // Check if syscall is hooked (outside kernel text section)
    bool is_hooked =
        (sys_call_addr < kernel_start_addr || sys_call_addr > kernel_end_addr);
    if (is_hooked) {
      log_debug("STATE_SYSCALL_TABLE: Hook detected: syscall %s at 0x%" PRIx64,
                sys_index[i], sys_call_addr);
      syscall_hit_count++;
    }

    // Add syscall information to data structure
    syscall_table_state_add_syscall(syscall_data, (uint32_t)i, sys_index[i],
                                    sys_call_addr, is_hooked);
  }

  // Set summary information
  syscall_table_state_set_summary(syscall_data, syscall_hit_count);

  if (syscall_hit_count > 0) {
    log_warn("STATE_SYSCALL_TABLE: %d syscalls appear to be hooked.",
             syscall_hit_count);
  } else {
    log_info("STATE_SYSCALL_TABLE: No hooked syscalls detected.");
  }

  // Clean up temporary data
  cleanup_sys_index(sys_index, syscall_number);

  // Queue success response
  int result = log_success_and_queue_response_task(
      "syscall_table_state", STATE_SYSCALL_TABLE, syscall_data,
      (void (*)(void*))syscall_table_state_data_free);

  log_info("STATE_SYSCALL_TABLE callback completed.");
  return result;
}