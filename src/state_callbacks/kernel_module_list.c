#include "state_callbacks/kernel_module_list.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include "event_handler.h"
#include "offsets.h"
#include "state_callbacks/responses/kernel_module_list_response.h"
#include "utils.h"

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

    // Convert state to string representation
    const char* state_str = "unknown";
    switch (state) {
      case 0:
        state_str = "live";
        break;
      case 1:
        state_str = "coming";
        break;
      case 2:
        state_str = "going";
        break;
      case 3:
        state_str = "unformed";
        break;
      default:
        state_str = "unknown";
        break;
    }

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

    // Convert module base to hex string for offset
    char offset_str[32];
    (void)snprintf(offset_str, sizeof(offset_str), "0x%" PRIx64,
                   (uint64_t)module_base);

    if (!modname) {
      log_debug(
          "STATE_KERNEL_MODULE_LIST: Failed to read module name at "
          "0x%" PRIx64,
          name_addr);
      // Add module with unknown name
      kernel_module_list_state_add_module(module_data, "unknown", 0, 0, NULL,
                                          state_str, offset_str,
                                          (uint64_t)module_base, is_suspicious);
    } else {
      log_debug(
          "STATE_KERNEL_MODULE_LIST: Module %d: %s "
          "[module_base=0x%" PRIx64 "]",
          ++count, modname, module_base);

      // Add module to data structure
      kernel_module_list_state_add_module(module_data, modname, 0, 0, NULL,
                                          state_str, offset_str,
                                          (uint64_t)module_base, is_suspicious);
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

  int result = log_success_and_queue_response_task(
      "kernel_module_list_state", STATE_KERNEL_MODULE_LIST, module_data,
      (void (*)(void*))kernel_module_list_state_data_free);

  log_info("STATE_KERNEL_MODULE_LIST callback completed.");
  return result;
}