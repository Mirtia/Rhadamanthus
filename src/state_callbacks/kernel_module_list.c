#include "state_callbacks/kernel_module_list.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include "event_handler.h"
#include "offsets.h"

uint32_t state_kernel_module_list_callback(vmi_instance_t vmi, void* context) {
  // Preconditions
  if (!vmi || !context) {
    log_error(
        "STATE_KERNEL_MODULE_LIST: Invalid arguments to kernel module "
        "list "
        "state callback.");
    return VMI_FAILURE;
  }

  event_handler_t* event_handler = (event_handler_t*)context;
  if (!event_handler || !event_handler->is_paused) {
    log_error(
        "STATE_KERNEL_MODULE_LIST: Callback requires a paused VM "
        "instance.");
    return VMI_FAILURE;
  }

  log_info("Executing STATE_KERNEL_MODULE_LIST callback.");

  addr_t modules_head = 0;
  if (vmi_read_addr_ksym(vmi, "modules", &modules_head) != VMI_SUCCESS) {
    log_error(
        "STATE_KERNEL_MODULE_LIST: Failed to resolve kernel symbol "
        "'modules'.");
    return VMI_FAILURE;
  }

  // Read head->next
  addr_t cur_node = 0;
  if (vmi_read_addr_va(vmi, modules_head, 0, &cur_node) != VMI_SUCCESS) {
    log_error(
        "STATE_KERNEL_MODULE_LIST: Failed to read modules->next at "
        "0x%" PRIx64,
        modules_head);
    return VMI_FAILURE;
  }

  int count = 0;
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

    if (!modname) {
      log_debug(
          "STATE_KERNEL_MODULE_LIST: Failed to read module name at "
          "0x%" PRIx64,
          name_addr);
    } else {
      log_debug(
          "STATE_KERNEL_MODULE_LIST: Module %d: %s "
          "[module_base=0x%" PRIx64 "]",
          ++count, modname, module_base);
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

  if (count == 0) {
    log_info(
        "STATE_KERNEL_MODULE_LIST: No kernel modules found (note: "
        "list may be "
        "tampered or empty).");
  } else {
    log_info("STATE_KERNEL_MODULE_LIST: Total kernel modules found: %d", count);
  }

  log_info("STATE_KERNEL_MODULE_LIST callback completed.");

  return VMI_SUCCESS;
}