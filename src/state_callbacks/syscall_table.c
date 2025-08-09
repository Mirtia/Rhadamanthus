#include "state_callbacks/syscall_table.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>

/**
 * @brief Cleans up the syscall index array.
 * 
 * @param sys_index The syscall index array to clean up.  
 * @param count The number of entries in the syscall index array.
 */
static void cleanup_sys_index(char** sys_index, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    g_free(sys_index[i]);
  }
  g_free(sys_index);
}

/**
 * @brief Parses the syscall index file to extract syscall names and their indices.
 * 
 * @param out_count Pointer to store the number of syscalls parsed.
 * @return char** An array of syscall names, or NULL on failure.
 */
static char** parse_syscall_index_file(size_t* out_count) {
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
      log_warn("Invalid index in line: %s", line);
      continue;
    }

    while (g_ascii_isspace(*endptr))
      endptr++;
    if (*endptr == '\0' || *endptr == '\n') {
      log_warn("Missing name in line: %s", line);
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
    // Note: We know that count >=0 here, so no need to check for g_realloc returning NULL.
    char** temp = g_realloc(sys_index, sizeof(char*) * (count + 1));
    sys_index = temp;
    sys_index[count++] = name;
  }

  (void)fclose(file);
  *out_count = count;
  return sys_index;
}

uint32_t state_syscall_table_callback(vmi_instance_t vmi, void* context) {
  (void)context;
  size_t syscall_number = 0;
  char** sys_index = parse_syscall_index_file(&syscall_number);
  if (!sys_index)
    return VMI_FAILURE;

  addr_t sys_call_table_addr = 0;
  addr_t sys_call_addr = 0;
  addr_t kernel_start = 0, kernel_end = 0;
  int syscall_hit_count = 0;

  if (vmi_translate_ksym2v(vmi, "sys_call_table", &sys_call_table_addr) ==
      VMI_FAILURE) {
    log_error("Failed to resolve sys_call_table.");
    cleanup_sys_index(sys_index, syscall_number);
    return VMI_FAILURE;
  }

  log_info("sys_call_table address: 0x%" PRIx64, sys_call_table_addr);

  if ((vmi_translate_ksym2v(vmi, "_stext", &kernel_start) == VMI_FAILURE ||
       vmi_translate_ksym2v(vmi, "_etext", &kernel_end) == VMI_FAILURE)) {
    log_error("Failed to resolve kernel .text boundaries.");
    cleanup_sys_index(sys_index, syscall_number);
    return VMI_FAILURE;
  }

  log_info("Kernel .text range: 0x%" PRIx64 " - 0x%" PRIx64, kernel_start,
           kernel_end);

  for (size_t i = 0; i < syscall_number; ++i) {
    if (vmi_read_addr_va(vmi, sys_call_table_addr + i * sizeof(addr_t), 0,
                         &sys_call_addr) == VMI_FAILURE) {
      log_warn("Failed to read syscall address at index %zu.", i);
      continue;
    }

    if (sys_call_addr < kernel_start || sys_call_addr > kernel_end) {
      log_warn("Hook detected: syscall %s at 0x%" PRIx64, sys_index[i],
               sys_call_addr);
      syscall_hit_count++;
    }
  }

  if (syscall_hit_count > 0) {
    log_info("%d syscalls appear to be hooked.", syscall_hit_count);
  } else {
    log_info("No hooked syscalls detected.");
  }

  cleanup_sys_index(sys_index, syscall_number);
  return VMI_SUCCESS;
}