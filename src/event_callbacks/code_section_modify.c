#include "event_callbacks/code_section_modify.h"

#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <log.h>
#include <stdint.h>
#include "event_callbacks/responses/code_section_modify_response.h"
#include "utils.h"

/**
 * @brief Resolve the kernel symbol for a given virtual address.
 * 
 * @param vmi The LibVMI instance.
 * @param virtual_addr Virtual address to resolve.
 * @return const char* Nearest (first-match) kernel symbol name, or NULL if not found.
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
  // Preconditions
  if (!vmi || !event) {
    return log_error_and_queue_response_event(
        "code_section_modify", EVENT_CODE_SECTION_MODIFY, INVALID_ARGUMENTS,
        "Invalid arguments to code section modify callback.");
  }

  log_info("CODE_SECTION_MODIFY event triggered.");

  const uint32_t vcpu_id = event->vcpu_id;

  uint64_t rip = 0, cr3 = 0, rsp = 0;
  if (get_standard_registers(vmi, vcpu_id, &rip, &cr3, &rsp) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "code_section_modify", EVENT_CODE_SECTION_MODIFY, VMI_OP_FAILURE,
        "Failed to get standard registers.");
  }

  const addr_t write_gla = event->mem_event.gla;
  const addr_t write_gpa =
      (event->mem_event.gfn << 12) | event->mem_event.offset;

  const char* ksym = NULL;
  // There is a chance gla may be 0 (GLA valid check).
  // e.g. something may have gone wrong with page-structure walks.
  if (write_gla) {
    ksym = resolve_kernel_symbol(vmi, write_gla);
  }

  code_section_modify_data_t* code_data = code_section_modify_data_new(
      vcpu_id, rip, rsp, cr3, write_gla, write_gpa, ksym);
  if (!code_data) {
    return log_error_and_queue_response_event(
        "code_section_modify", EVENT_CODE_SECTION_MODIFY,
        MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for code section modify data.");
  }

  log_warn("CODE_SECTION_WRITE: VCPU=%u RIP=0x%" PRIx64 " GLA=0x%" PRIx64
           " GPA=0x%" PRIx64 "%s%s",
           vcpu_id, rip, (uint64_t)write_gla, (uint64_t)write_gpa,
           ksym ? " SYMBOL=" : "", ksym ? ksym : "");

  // 😩 😩 😩 😩 😩 😩 😩 😩 😩 😩 😩 😩 😩 😩 😩
  vmi_clear_event(vmi, event, NULL);
  vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);

  return log_success_and_queue_response_event(
      "code_section_modify", EVENT_CODE_SECTION_MODIFY, (void*)code_data,
      (void (*)(void*))code_section_modify_data_free);
}