#include "event_callbacks/code_section_modify.h"

#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <log.h>
#include <stdint.h>

/**
 * @brief Resolve the nearest kernel symbol for a given virtual address.
 *
 * @details LibVMI exposes vmi_translate_v2ksym() which looks up
 * the closest symbol from the loaded System.map (KASLR handled by LibVMI).
 * 
 * @param vmi LibVMI instance.
 * @param virtual_addr Virtual address to resolve.
 * @return const char* Nearest kernel symbol name, or NULL if not found.
 */
static inline const char* resolve_kernel_symbol(vmi_instance_t vmi,
                                                addr_t virtual_addr) {
  access_context_t ctx = {.version = ACCESS_CONTEXT_VERSION,
                          .translate_mechanism = VMI_TM_NONE,
                          .addr = 0,
                          .dtb = 0};
  return vmi_translate_v2ksym(vmi, &ctx, virtual_addr);
}

event_response_t event_code_section_modify_callback(vmi_instance_t vmi,
                                                    vmi_event_t* event) {
  if (!vmi || !event) {
    log_error("CODE_SECTION_WRITE: Invalid callback arguments");
    return VMI_EVENT_RESPONSE_NONE;
  }

  log_warn("CODE_SECTION_WRITE event triggered.");

  const uint32_t vcpu_id = event->vcpu_id;

  uint64_t rip = 0;
  (void)vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id);

  const addr_t write_gla = event->mem_event.gla;
  // On x86-64 with 4 KiB pages, the lowest 12 bits (page offset) are
  // preserved by the MMU translation, GFN indexes 4 KiB frames.
  const addr_t write_gpa = (event->mem_event.gfn << 12)  // 4 KiB page base.
                           |
                           // Offset in page.
                           event->mem_event.offset;

  const char* ksym = NULL;
  // There is a chance gla may be 0 (GLA valid check).
  // e.g. something may have gone wrong with page-structure walks.
  if (write_gla) {
    ksym = resolve_kernel_symbol(vmi, write_gla);
  }

  log_warn("CODE_SECTION_WRITE: VCPU=%u RIP=0x%" PRIx64 " GLA=0x%" PRIx64
           " GPA=0x%" PRIx64 "%s%s",
           vcpu_id, rip, (uint64_t)write_gla, (uint64_t)write_gpa,
           ksym ? " SYMBOL=" : "", ksym ? ksym : "");

  return VMI_EVENT_RESPONSE_NONE;
}
