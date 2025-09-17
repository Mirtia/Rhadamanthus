#include "state_callbacks/dir_string_matching.h"
#include <glib.h>
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef KNOWN_FILES_FILE
#define KNOWN_FILES_FILE "data/known_files.linux"
#endif

/**
 * @brief Load known files/directories from the known_files.linux file
 * 
 * @return GPtrArray* Array of known file/directory paths, or NULL on failure
 */
static GPtrArray* load_known_files() {
  GPtrArray* known_files = g_ptr_array_new_with_free_func(g_free);

  FILE* file = fopen(KNOWN_FILES_FILE, "r");
  if (!file) {
    log_warn("Failed to open known files file: %s. Proceeding with empty list.",
             KNOWN_FILES_FILE);
    return known_files;
  }

  char line[512];
  while (fgets(line, sizeof(line), file)) {
    // Remove trailing newline and whitespace
    char* trimmed = g_strstrip(line);

    // Skip empty lines and comments
    if (strlen(trimmed) == 0 || trimmed[0] == '#') {
      continue;
    }

    // Add to known files list
    g_ptr_array_add(known_files, g_strdup(trimmed));
  }

  fclose(file);
  log_info("Loaded %u known files/directories from %s",
           (unsigned int)known_files->len, KNOWN_FILES_FILE);

  return known_files;
}

/**
 * @brief Check if a file/directory path matches any known suspicious paths
 * 
 * @param path The path to check
 * @param known_files Array of known suspicious paths
 * @return true if path matches a known suspicious path, false otherwise
 */
static bool is_known_suspicious_path(const char* path, GPtrArray* known_files) {
  if (!path || !known_files) {
    return false;
  }

  for (guint i = 0; i < known_files->len; i++) {
    const char* known_path = (const char*)g_ptr_array_index(known_files, i);
    if (strstr(path, known_path) != NULL) {
      return true;
    }
  }

  return false;
}

uint32_t state_dir_string_matching_callback(vmi_instance_t vmi, void* context) {
  (void)context;

  log_info("Executing STATE_DIR_STRING_MATCHING callback.");

  // Load known suspicious files/directories
  GPtrArray* known_files = load_known_files();
  if (!known_files) {
    log_error("Failed to load known files list");
    return VMI_FAILURE;
  }

  // TODO: Implement actual VMI-based file system inspection
  // This would involve:
  // 1. Walking the file system through VMI
  // 2. Checking for files/directories that exist in memory but are hidden from userspace
  // 3. Comparing against the known_files list
  // 4. Reporting any matches as potential rootkit activity

  log_info(
      "Known files loaded successfully. File system inspection not yet "
      "implemented.");
  log_info(
      "This callback would detect files/directories that exist in kernel "
      "memory");
  log_info(
      "but are hidden from userspace, indicating potential rootkit activity.");

  // Clean up
  g_ptr_array_free(known_files, TRUE);

  return VMI_SUCCESS;
}
