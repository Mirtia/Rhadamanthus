#include "state_callbacks/kernel_module_list.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <string.h>
#include "event_handler.h"
#include "offsets.h"
#include "state_callbacks/responses/kernel_module_list_response.h"
#include "utils.h"

// Module state enum values (from Linux kernel)
#define MODULE_STATE_LIVE 0
#define MODULE_STATE_COMING 1
#define MODULE_STATE_GOING 2
#define MODULE_STATE_UNFORMED 3

// Maximum module name length in Linux kernel
#define MODULE_NAME_LEN 56

/**
 * @brief Convert module state enum to string representation
 * 
 * @param state Module state value
 * @return String representation of the state
 */
static const char* get_module_state_string(uint32_t state) {
  switch (state) {
    case MODULE_STATE_LIVE:
      return "live";
    case MODULE_STATE_COMING:
      return "coming";
    case MODULE_STATE_GOING:
      return "going";
    case MODULE_STATE_UNFORMED:
      return "unformed";
    default:
      return "unknown";
  }
}

/**
 * @brief Format module base address as hex string
 * 
 * @param buffer Output buffer (must be at least 32 bytes)
 * @param buffer_size Size of output buffer
 * @param module_base Module base address
 */
static void format_module_offset(char* buffer, size_t buffer_size,
                                 addr_t module_base) {
  (void)snprintf(buffer, buffer_size, "0x%" PRIx64, (uint64_t)module_base);
}

#ifdef BRUTEFORCE_MODULE_SCAN
// Alignment of struct module (typically 8 bytes on x86_64)
#define MODULE_STRUCT_ALIGNMENT 8

/**
 * @brief Check if an address is within the kernel module address space
 * 
 * @param addr Address to check
 * @return true if address is in module space, false otherwise
 */
static inline bool is_in_module_space(addr_t addr) {
  return (addr >= LINUX_MODULE_START && addr <= LINUX_MODULE_END);
}

/**
 * @brief Validate if memory at given address looks like a struct module
 * 
 * Uses heuristics inspired by Phrack 71:12 and rkchk:
 * - state field must be a known enum value
 * - name is a valid null-terminated string
 * - core_layout.size is non-zero and page-aligned
 * - core_layout.base points to module address space
 * 
 * @param vmi VMI instance
 * @param addr Address to check
 * @param score_out Output score (higher = more likely to be a module)
 * @return true if likely a valid struct module, false otherwise
 */
static bool validate_module_struct(vmi_instance_t vmi, addr_t addr,
                                   int* score_out) {
  int score = 0;

  // Check state field
  uint32_t state = 0;
  if (vmi_read_32_va(vmi, addr + LINUX_MODULE_STATE_OFFSET, 0, &state) ==
      VMI_SUCCESS) {
    if (state == MODULE_STATE_LIVE || state == MODULE_STATE_COMING ||
        state == MODULE_STATE_GOING || state == MODULE_STATE_UNFORMED) {
      score++;
    }
  }

  // Check name field - must be a valid null-terminated string
  char name_buf[MODULE_NAME_LEN];
  memset(name_buf, 0, sizeof(name_buf));
  size_t bytes_read = 0;
  if (vmi_read_va(vmi, addr + LINUX_MODULE_NAME_OFFSET, 0, MODULE_NAME_LEN - 1,
                  name_buf, &bytes_read) == VMI_SUCCESS) {
    name_buf[MODULE_NAME_LEN - 1] = '\0';
    size_t name_len = strnlen(name_buf, MODULE_NAME_LEN);

    // Module name must be at least 2 chars and less than max
    // Most real modules are 3+ chars (e.g., ext4, usb, nfs)
    if (name_len >= 2 && name_len < MODULE_NAME_LEN) {
      // Check if name contains only valid module name characters
      // Valid: alphanumeric, underscore, hyphen
      bool valid_chars = true;
      bool has_alpha = false;  // Must have at least one letter

      for (size_t i = 0; i < name_len; i++) {
        char chr = name_buf[i];
        // Check for valid characters: a-z, A-Z, 0-9, _, -
        if (!((chr >= 'a' && chr <= 'z') || (chr >= 'A' && chr <= 'Z') ||
              (chr >= '0' && chr <= '9') || chr == '_' || chr == '-')) {
          valid_chars = false;
          break;
        }
        // Track if we have letters (not just numbers/underscores)
        if ((chr >= 'a' && chr <= 'z') || (chr >= 'A' && chr <= 'Z')) {
          has_alpha = true;
        }
      }

      // Score only if valid chars AND has at least one letter
      if (valid_chars && has_alpha) {
        score++;
      }
    }
  }

  // Check core_layout.size (page-aligned)
  uint32_t core_size = 0;
  if (vmi_read_32_va(vmi, addr + LINUX_MODULE_CORE_LAYOUT_OFFSET + 8, 0,
                     &core_size) == VMI_SUCCESS) {
    if (core_size > 0 && (core_size % 4096) == 0) {
      score++;
    }
  }

  // Check core_layout.base (valid module address)
  addr_t core_base = 0;
  if (vmi_read_addr_va(vmi, addr + LINUX_MODULE_CORE_LAYOUT_OFFSET, 0,
                       &core_base) == VMI_SUCCESS) {
    if (is_in_module_space(core_base)) {
      score++;
    }
  }

  if (score_out) {
    *score_out = score;
  }

  // Require ALL 4 heuristics to pass to minimize false positives
  // This is stricter than rkchk's 3/4, but necessary for VMI-based scanning
  return score == 4;
}

/**
 * @brief Perform independent bruteforce scan for kernel modules
 * 
 * This function performs a standalone bruteforce scan of the kernel module
 * address space to detect modules using heuristic validation. It compares
 * found modules with the linked list to identify hidden modules.
 * 
 * Based on the technique from Phrack 71:12 and rkchk implementation.
 * 
 * @param vmi VMI instance
 * @param module_data Module data structure to add HIDDEN modules to
 * @param list_modules Hash table of modules from linked list (for comparison)
 * @return Number of HIDDEN modules found (not in linked list)
 */
static int perform_bruteforce_module_scan(
    vmi_instance_t vmi, kernel_module_list_state_data_t* module_data,
    GHashTable* list_modules) {

  int found_count = 0;
  addr_t current_addr = LINUX_MODULE_START;

  log_info(
      "BRUTEFORCE_SCAN: Starting bruteforce scan of module address space "
      "(0x%lx - 0x%lx)",
      LINUX_MODULE_START, LINUX_MODULE_END);

  // Scan the entire module address space
  while (current_addr < LINUX_MODULE_END) {
    int score = 0;

    // Check if this looks like a valid struct module
    if (validate_module_struct(vmi, current_addr, &score)) {
      // Read the module name
      char name_buf[MODULE_NAME_LEN];
      memset(name_buf, 0, sizeof(name_buf));
      if (vmi_read_va(vmi, current_addr + LINUX_MODULE_NAME_OFFSET, 0,
                      MODULE_NAME_LEN - 1, name_buf, NULL) == VMI_SUCCESS) {
        name_buf[MODULE_NAME_LEN - 1] = '\0';

        // Skip if name is empty (already filtered by validation, but double-check)
        if (strlen(name_buf) < 2) {
          current_addr += MODULE_STRUCT_ALIGNMENT;
          continue;
        }

        // Read module state
        uint32_t state = 0;
        vmi_read_32_va(vmi, current_addr + LINUX_MODULE_STATE_OFFSET, 0,
                       &state);
        const char* state_str = get_module_state_string(state);

        // Format offset string
        char offset_str[32];
        format_module_offset(offset_str, sizeof(offset_str), current_addr);

        // Check if this module was in the linked list
        // NOLINTNEXTLINE(performance-no-int-to-ptr)
        bool in_list =
            g_hash_table_contains(list_modules, GSIZE_TO_POINTER(current_addr));
        bool is_hidden = !in_list;

        if (is_hidden) {
          // HIDDEN MODULE - only found via bruteforce, not in linked list!
          log_warn(
              "BRUTEFORCE_SCAN: *** HIDDEN MODULE *** '%s' at %s (state: %s, "
              "score: %d) - NOT in linked list!",
              name_buf, offset_str, state_str, score);

          // Add to results marked as suspicious
          kernel_module_list_state_add_module(module_data, name_buf, 0, 0, NULL,
                                              state_str, offset_str,
                                              (uint64_t)current_addr, true);
          found_count++;
        } else {
          // Module is in both linked list and bruteforce - normal, skip to avoid duplicates
          log_debug(
              "BRUTEFORCE_SCAN: Module '%s' at %s confirmed in both lists "
              "(state: %s, score: %d)",
              name_buf, offset_str, state_str, score);
        }

        // Skip ahead to avoid finding the same module multiple times
        current_addr += 4096;
        continue;
      }
    }

    // Advance by alignment
    current_addr += MODULE_STRUCT_ALIGNMENT;

    // Safety limit to prevent excessive scanning
    if (found_count > 1000) {
      log_warn("BRUTEFORCE_SCAN: Found >1000 candidates, stopping");
      break;
    }
  }

  log_info(
      "BRUTEFORCE_SCAN: Complete, found %d HIDDEN modules (not in linked list)",
      found_count);
  return found_count;
}
#endif  // BRUTEFORCE_MODULE_SCAN

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
uint32_t state_kernel_module_list_callback(vmi_instance_t vmi, void* context) {
  // Preconditions
  if (!vmi || !context) {
    return log_error_and_queue_response_task(
        "kernel_module_list_state", STATE_KERNEL_MODULE_LIST, INVALID_ARGUMENTS,
        "STATE_KERNEL_MODULE_LIST: Invalid arguments to kernel module list "
        "state callback");
  }

  event_handler_t* event_handler = (event_handler_t*)context;
  if (!event_handler || !event_handler->is_paused) {
    return log_error_and_queue_response_task(
        "kernel_module_list_state", STATE_KERNEL_MODULE_LIST, INVALID_ARGUMENTS,
        "STATE_KERNEL_MODULE_LIST: Callback requires a valid event handler "
        "context");
  }

  log_info("Executing STATE_KERNEL_MODULE_LIST callback.");

  // Create kernel module list state data structure
  kernel_module_list_state_data_t* module_data =
      kernel_module_list_state_data_new();
  if (!module_data) {
    return log_error_and_queue_response_task(
        "kernel_module_list_state", STATE_KERNEL_MODULE_LIST,
        MEMORY_ALLOCATION_FAILURE,
        "STATE_KERNEL_MODULE_LIST: Failed to allocate memory for kernel module "
        "list state data");
  }

  addr_t modules_head = 0;
  if (vmi_read_addr_ksym(vmi, "modules", &modules_head) != VMI_SUCCESS) {
    kernel_module_list_state_data_free(module_data);
    return log_error_and_queue_response_task(
        "kernel_module_list_state", STATE_KERNEL_MODULE_LIST, VMI_OP_FAILURE,
        "STATE_KERNEL_MODULE_LIST: Failed to resolve kernel symbol 'modules'");
  }

  // Read head->next
  addr_t cur_node = 0;
  if (vmi_read_addr_va(vmi, modules_head, 0, &cur_node) != VMI_SUCCESS) {
    kernel_module_list_state_data_free(module_data);
    return log_error_and_queue_response_task(
        "kernel_module_list_state", STATE_KERNEL_MODULE_LIST, VMI_OP_FAILURE,
        "STATE_KERNEL_MODULE_LIST: Failed to read modules->next");
  }

  int count = 0;
  uint32_t suspicious_modules = 0;

#ifdef BRUTEFORCE_MODULE_SCAN
  // Create hash table to track modules found in linked list (for comparison)
  // Key: module_base address, Value: module name
  GHashTable* list_modules =
      g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
#endif

  while (cur_node && cur_node != modules_head) {
    // cur_node points to `struct module::list` (a list_head inside the module)
    addr_t module_base = cur_node - LINUX_MODULE_LIST_OFFSET;

    // Read module->name (NUL-terminated char array)
    addr_t name_addr = module_base + LINUX_MODULE_NAME_OFFSET;
    gchar* modname = vmi_read_str_va(vmi, name_addr, 0);
    uint32_t state = 0;

    if (vmi_read_32_va(vmi, module_base + LINUX_MODULE_STATE_OFFSET, 0,
                       &state) != VMI_SUCCESS) {
      log_debug(
          "STATE_KERNEL_MODULE_LIST: Failed to read module state at "
          "0x%" PRIx64,
          module_base + LINUX_MODULE_STATE_OFFSET);
      state = 0xFFFFFFFF;  // Erroneous state.
    }

    const char* state_str = get_module_state_string(state);

    // Check if module is suspicious (basic heuristics)
    bool is_suspicious = false;
    if (modname) {
      // Check for common rootkit module names or patterns
      if (strstr(modname, "rootkit") || strstr(modname, "backdoor") ||
          strstr(modname, "stealth") || strstr(modname, "hidden")) {
        is_suspicious = true;
      }
      // Check for modules with very short names (suspicious)
      if (strlen(modname) < 3) {
        is_suspicious = true;
      }
    }

    if (is_suspicious) {
      suspicious_modules++;
    }

    char offset_str[32];
    format_module_offset(offset_str, sizeof(offset_str), module_base);

    if (!modname) {
      log_debug(
          "STATE_KERNEL_MODULE_LIST: Failed to read module name at "
          "0x%" PRIx64,
          name_addr);
      // Add module with unknown name
      kernel_module_list_state_add_module(module_data, "unknown", 0, 0, NULL,
                                          state_str, offset_str,
                                          (uint64_t)module_base, is_suspicious);
#ifdef BRUTEFORCE_MODULE_SCAN
      // Track in hash table for comparison
      // NOLINTNEXTLINE(performance-no-int-to-ptr)
      g_hash_table_insert(list_modules, GSIZE_TO_POINTER(module_base),
                          g_strdup("unknown"));
#endif
    } else {
      log_debug(
          "STATE_KERNEL_MODULE_LIST: Module %d: %s "
          "[module_base=0x%" PRIx64 "]",
          ++count, modname, module_base);

      // Add module to data structure
      kernel_module_list_state_add_module(module_data, modname, 0, 0, NULL,
                                          state_str, offset_str,
                                          (uint64_t)module_base, is_suspicious);

#ifdef BRUTEFORCE_MODULE_SCAN
      // Track in hash table for comparison
      // NOLINTNEXTLINE(performance-no-int-to-ptr)
      g_hash_table_insert(list_modules, GSIZE_TO_POINTER(module_base),
                          g_strdup(modname));
#endif

      g_free(modname);
    }

    if (vmi_read_addr_va(vmi, cur_node, 0, &cur_node) != VMI_SUCCESS) {
      log_warn(
          "STATE_KERNEL_MODULE_LIST: Failed to read list->next at "
          "0x%" PRIx64,
          cur_node);
      break;
    }
  }

  // Set summary information
  kernel_module_list_state_set_summary(module_data, count, suspicious_modules);

  if (count == 0) {
    log_info(
        "STATE_KERNEL_MODULE_LIST: No kernel modules found (note: "
        "list may be "
        "tampered or empty).");
  } else {
    log_info("STATE_KERNEL_MODULE_LIST: Total kernel modules found: %d", count);
  }

  if (suspicious_modules > 0) {
    log_warn("STATE_KERNEL_MODULE_LIST: Found %u suspicious modules.",
             suspicious_modules);
  } else {
    log_info("STATE_KERNEL_MODULE_LIST: No suspicious modules detected");
  }

#ifdef BRUTEFORCE_MODULE_SCAN
  // Perform independent bruteforce scan with comparison
  log_info(
      "STATE_KERNEL_MODULE_LIST: Bruteforce scanning enabled, comparing with "
      "linked list");
  log_info("STATE_KERNEL_MODULE_LIST: Linked list found %d modules", count);

  // Returns number of HIDDEN modules (not in linked list)
  int hidden_modules =
      perform_bruteforce_module_scan(vmi, module_data, list_modules);

  if (hidden_modules > 0) {
    log_warn(
        "STATE_KERNEL_MODULE_LIST: *** ALERT *** Detected %d HIDDEN MODULE(S)!",
        hidden_modules);
    log_warn(
        "STATE_KERNEL_MODULE_LIST: These modules are NOT in the kernel linked "
        "list but found via memory scan!");
    suspicious_modules += hidden_modules;
  } else {
    log_info(
        "STATE_KERNEL_MODULE_LIST: Bruteforce scan complete - all modules "
        "match linked list");
    log_info("STATE_KERNEL_MODULE_LIST: No hidden modules detected");
  }

  // Clean up hash table
  g_hash_table_destroy(list_modules);

  // Update total count and summary (hidden modules already added to module_data)
  count += hidden_modules;
  kernel_module_list_state_set_summary(module_data, count, suspicious_modules);
#endif

  log_info("STATE_KERNEL_MODULE_LIST callback completed.");
  return log_success_and_queue_response_task(
      "kernel_module_list_state", STATE_KERNEL_MODULE_LIST, module_data,
      (void (*)(void*))kernel_module_list_state_data_free);
}