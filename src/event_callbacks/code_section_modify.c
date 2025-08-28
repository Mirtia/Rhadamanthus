#include "event_callbacks/code_section_modify.h"

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <inttypes.h>
#include <log.h>

/**
 * @brief Resolve a kernel symbol name for a given virtual address.
 *
 * @param vmi The VMI instance. 
 * @param virtual_addr The virtual address to resolve.
 * @return const char* 
 */
static inline const char* resolve_kernel_symbol(vmi_instance_t vmi, addr_t virtual_addr) {
    access_context_t ctx = {
        .version = ACCESS_CONTEXT_VERSION,
        .translate_mechanism = VMI_TM_KERNEL_SYMBOL,
        .addr = virtual_addr,
        .dtb = 0
    };
    return vmi_translate_v2ksym(vmi, &ctx, virtual_addr);
}

event_response_t event_code_section_modify_callback(vmi_instance_t vmi,
                                                    vmi_event_t* event) {
    const uint32_t vcpu_id = event->vcpu_id;

    uint64_t rip = 0;
    (void)vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id);

    // Guest linear (VA) and guest physical (derived from GFN)
    addr_t write_gla = event->mem_event.gla;                  // may be 0
    addr_t write_pa  = (event->mem_event.gfn << 12)           // shift GFN by page size (4K)
                       + event->mem_event.offset;             // add intra-page offset

    // Try to resolve symbol (only if we have a valid VA)
    const char* ksym = NULL;
    if (write_gla) {
        ksym = resolve_kernel_symbol(vmi, write_gla);
    }

    log_warn("CODE SECTION WRITE: VCPU=%u RIP=0x%" PRIx64
             " GLA=0x%" PRIx64 " GPA=0x%" PRIx64 "%s%s",
             vcpu_id, rip,
             (uint64_t)write_gla, (uint64_t)write_pa,
             ksym ? " SYMBOL=" : "",
             ksym ? ksym : "");

    // TODO(MGkolemi): Remove? double-check VA→PA translation
    // if (write_gla) {
    //     addr_t pa = 0;
    //     if (vmi_translate_kv2p(vmi, write_gla, &pa) == VMI_SUCCESS) {
    //         log_debug("KV→PA: VA=0X%" PRIx64 " → PA=0x%" PRIx64,
    //                  (uint64_t)write_gla, (uint64_t)pa);
    //     }
    // }

    return VMI_EVENT_RESPONSE_NONE;
}
