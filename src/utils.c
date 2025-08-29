#include "utils.h"

#include <log.h>

uint32_t get_kernel_text_section_range(vmi_instance_t vmi, addr_t* start_addr,
                                       addr_t* end_addr) {
  if (!vmi) {
    log_error("Vmi instance is uninitialized.");
    return VMI_FAILURE;
  }

  if ((vmi_translate_ksym2v(vmi, "_stext", start_addr) == VMI_FAILURE ||
       vmi_translate_ksym2v(vmi, "_etext", end_addr) == VMI_FAILURE)) {
    log_error("Failed to resolve kernel .text boundaries.");
    return VMI_FAILURE;
  }

  return VMI_SUCCESS;
}