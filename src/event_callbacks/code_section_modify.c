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
 * The access_context is ignored for Linux here.
 * Docs/API: vmi_translate_v2ksym / vmi_translate_v2sym. 
 *   - LibVMI API reference (symbols): libvmi.com/api (see v2ksym/v2sym entries).
 * 
 * @param vmi LibVMI instance.
 * @param va Virtual address to resolve.
 * @return const char* Nearest kernel symbol name, or NULL if not found.
 */
static inline const char* resolve_kernel_symbol(vmi_instance_t vmi, addr_t va) {
  access_context_t ctx = {.version = ACCESS_CONTEXT_VERSION,
                          .translate_mechanism = VMI_TM_NONE,
                          .addr = 0,
                          .dtb = 0};
  return vmi_translate_v2ksym(vmi, &ctx, va);
}

event_response_t event_code_section_modify_callback(vmi_instance_t vmi,
                                                    vmi_event_t* event) {
  if (!vmi || !event) {
    log_error("CODE SECTION WRITE: invalid callback arguments");
    return VMI_EVENT_RESPONSE_NONE;
  }

  const uint32_t vcpu_id = event->vcpu_id;

  uint64_t rip = 0;
  (void)vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id);

  /*
   * - gfn   : guest frame number (4 KiB frames)
   * - offset: byte offset within that 4 KiB frame
   * - gla   : guest linear (virtual) address, may be 0 if unavailable
   * Example usage in LibVMI Xen examples shows GFN and offset used together.
   *   (See libvmi-xen event examples that log "GFN ... (offset ...)"). 
   */
  const addr_t write_gla = event->mem_event.gla;        /* may be 0 */
  const addr_t write_gpa = (event->mem_event.gfn << 12) /* 4 KiB page base */
                           | event->mem_event.offset;   /* intra-page offset */

  /*
   * On x86-64 with 4 KiB pages, the lowest 12 bits (page offset) are
   * preserved by the MMU translation; GFN indexes 4 KiB frames.
   * Intel SDM (paging): page-offset bits are not translated for 4 KiB pages.
   */
  const char* ksym = NULL;
  if (write_gla) {
    ksym = resolve_kernel_symbol(vmi, write_gla);
  }

  log_warn("CODE SECTION WRITE: VCPU=%u RIP=0x%" PRIx64 " GLA=0x%" PRIx64
           " GPA=0x%" PRIx64 "%s%s",
           vcpu_id, rip, (uint64_t)write_gla, (uint64_t)write_gpa,
           ksym ? " SYMBOL=" : "", ksym ? ksym : "");

  return VMI_EVENT_RESPONSE_NONE;
}
