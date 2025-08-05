#include "state_callbacks/module_list.h"
#include <log.h>

uint32_t state_module_list_callback(vmi_instance_t vmi, void* context) {
  log_info("Executing STATE_KERNEL_MODULE_LIST callback.");
  return VMI_SUCCESS;
}
