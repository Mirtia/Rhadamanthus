#include "utils.h"

#include <inttypes.h>
#include <log.h>

uint32_t get_kernel_text_section_range(vmi_instance_t vmi, addr_t* start_addr,
                                       addr_t* end_addr) {
  if (!vmi) {
    log_debug("VMI instance is uninitialized.");
    return VMI_FAILURE;
  }

  if ((vmi_translate_ksym2v(vmi, "_stext", start_addr) == VMI_FAILURE ||
       vmi_translate_ksym2v(vmi, "_etext", end_addr) == VMI_FAILURE)) {
    log_debug("Failed to resolve kernel .text boundaries.");
    return VMI_FAILURE;
  }

  return VMI_SUCCESS;
}

bool is_in_kernel_text(vmi_instance_t vmi, addr_t addr) {

  if (!vmi) {
    log_debug("VMI instance is uninitialized.");
    return false;
  }

  addr_t start_addr = 0, end_addr = 0;

  if (get_kernel_text_section_range(vmi, &start_addr, &end_addr) !=
      VMI_SUCCESS) {
    log_debug("Unable to get kernel text section range for address check.");
    return false;
  }
  // Kernel bounds: [start_addr, end_addr)
  return (addr >= start_addr && addr < end_addr);
}

void log_vcpu_state(vmi_instance_t vmi, uint32_t vcpu_id, addr_t kaddr,
                    const char* context) {
  if (!vmi) {
    log_warn("log_vcpu_state: Invalid VMI instance");
    return;
  }

  reg_t rip = 0, rflags = 0;
  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    log_warn("log_vcpu_state: Failed to get RIP for vCPU %u", vcpu_id);
    rip = 0;
  }

  if (vmi_get_vcpureg(vmi, &rflags, RFLAGS, vcpu_id) != VMI_SUCCESS) {
    log_warn("log_vcpu_state: Failed to get RFLAGS for vCPU %u", vcpu_id);
    rflags = 0;
  }

  uint8_t byte_at_kaddr = 0;
  if (kaddr != 0) {
    if (vmi_read_8_va(vmi, kaddr, 0, &byte_at_kaddr) != VMI_SUCCESS) {
      log_warn("log_vcpu_state: Failed to read byte at 0x%" PRIx64, kaddr);
      // Sentinel value.
      byte_at_kaddr = 0xFF;
  }

  unsigned int tf_flag = (unsigned int)((rflags >> 8) & 1);

  if (kaddr != 0) {
    log_info("%s state: RIP=0x%" PRIx64 " TF=%u byte@0x%" PRIx64
             "=0x%02x vCPU=%u",
             context ? context : "VCPU", (uint64_t)rip, tf_flag, kaddr,
             byte_at_kaddr, vcpu_id);
  } else {
    log_info("%s state: RIP=0x%" PRIx64 " TF=%u vCPU=%u",
             context ? context : "VCPU", (uint64_t)rip, tf_flag, vcpu_id);
  }
}