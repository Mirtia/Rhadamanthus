#include "state_callbacks/kernel_module_list.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>

uint32_t state_kernel_module_list_callback(vmi_instance_t vmi, void* context) {
  (void)context;

  addr_t list_head = 0;
  addr_t next_module = 0;

  if (vmi_read_addr_ksym(vmi, "modules", &next_module) == VMI_FAILURE) {
    log_error("Failed to resolve kernel symbol 'modules'.");
    return VMI_FAILURE;
  }

  list_head = next_module;
  int count = 0;

  while (true) {
    addr_t tmp_next = 0;

    if (vmi_read_addr_va(vmi, next_module, 0, &tmp_next) == VMI_FAILURE) {
      log_warn("Failed to read next module pointer at address 0x%" PRIx64,
               next_module);
      break;
    }

    if (tmp_next == list_head) {
      break;
    }

    size_t name_offset = (vmi_get_page_mode(vmi, 0) == VMI_PM_IA32E) ? 16 : 8;

    gchar* modname = vmi_read_str_va(vmi, next_module + name_offset, 0);
    if (!modname) {
      log_warn("Failed to read module name at 0x%" PRIx64,
               next_module + name_offset);
    } else {
      log_info("Module %d: %s [addr=0x%" PRIx64 "]", ++count, modname,
               next_module);
      g_free(modname);
    }

    next_module = tmp_next;
  }

  if (count == 0) {
    log_info("No kernel modules found.");
  } else {
    log_info("Total kernel modules found: %d", count);
  }

  return VMI_SUCCESS;
}
