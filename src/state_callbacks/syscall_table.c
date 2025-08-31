#include "state_callbacks/syscall_table.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include "event_handler.h"
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
    log_debug("Failed to open syscall index file: %s", SYSCALL_INDEX_FILE);
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
      log_debug("Endptr was NULL. Strdup failed for line: %s", line);
      (void)fclose(file);
      cleanup_sys_index(sys_index, count);
      return NULL;
    }

    name[strcspn(name, "\r\n")] = '\0';
    char** temp = g_realloc(sys_index, sizeof(char*) * (count + 1));
    if (!temp) {
      log_debug("Realloc failed while expanding syscall index array.");
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
    log_error("STATE_SYSCALL_TABLE: Invalid input parameters.");
    return VMI_FAILURE;
  }

  event_handler_t* event_handler = (event_handler_t*)context;
  // By not having a paused VM we risk inconsistent state between information gathering (reads).
  if (!event_handler || !event_handler->is_paused) {
    log_error("STATE_SYSCALL_TABLE: Callback requires a paused VM.");
    return VMI_FAILURE;
  }

  log_info("Executing STATE_SYSCALL_TABLE callback.");

  size_t syscall_number = 0;
  // In `data` folder, in the root repository, there is an index of the system calls available to the target system.
  char** sys_index = parse_syscall_index_file(&syscall_number);
  if (!sys_index)
    return VMI_FAILURE;

  addr_t sys_call_table_addr = 0;
  addr_t sys_call_addr = 0;
  addr_t kernel_start = 0, kernel_end = 0;
  int syscall_hit_count = 0;

  if (vmi_translate_ksym2v(vmi, "sys_call_table", &sys_call_table_addr) ==
      VMI_FAILURE) {
    log_error("STATE_SYSCALL_TABLE: Failed to resolve symbol sys_call_table.");
    cleanup_sys_index(sys_index, syscall_number);
    return VMI_FAILURE;
  }

  log_info("STATE_SYSCALL_TABLE: sys_call_table address: 0x%" PRIx64,
           sys_call_table_addr);

  if (get_kernel_text_section_range(vmi, &kernel_start, &kernel_end) ==
      VMI_FAILURE) {
    log_error(
        "STATE_SYSCALL_TABLE: Failed to get kernel .text section boundaries.");
    cleanup_sys_index(sys_index, syscall_number);
    return VMI_FAILURE;
  }

  log_info("STATE_SYSCALL_TABLE: .text range: 0x%" PRIx64 " - 0x%" PRIx64,
           kernel_start, kernel_end);

  for (size_t i = 0; i < syscall_number; ++i) {
    if (vmi_read_addr_va(vmi, sys_call_table_addr + i * sizeof(addr_t), 0,
                         &sys_call_addr) == VMI_FAILURE) {
      log_warn(
          "STATE_SYSCALL_TABLE: Failed to read syscall address at index %zu.",
          i);
      continue;
    }
    
    // It is suspicious that the hook is outside the kernel text section.
    if (sys_call_addr < kernel_start || sys_call_addr > kernel_end) {
      log_warn("STATE_SYSCALL_TABLE: Hook detected: syscall %s at 0x%" PRIx64,
               sys_index[i], sys_call_addr);
      syscall_hit_count++;
    }
  }

  if (syscall_hit_count > 0) {
    log_warn("STATE_SYSCALL_TABLE: %d syscalls appear to be hooked.",
             syscall_hit_count);
  } else {
    log_info("STATE_SYSCALL_TABLE: No hooked syscalls detected.");
  }

  cleanup_sys_index(sys_index, syscall_number);
  log_info("STATE_SYSCALL_TABLE callback completed.");
  return VMI_SUCCESS;
}