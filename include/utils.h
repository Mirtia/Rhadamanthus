#ifndef UTILS_H
#define UTILS_H
#include <libvmi/libvmi.h>

/**
 * @brief Get the kernel .text section start and end address.
 * 
 * @param vmi The VMI instance.
 * @param start_addr The output start address of the kernel text section.
 * @param end_addr The output end address of the kernel text section.
 * @return uint32_t VMI_SUCCESS on success, VMI_FAILURE on failure
 */
uint32_t get_kernel_text_section_range(vmi_instance_t vmi, addr_t* start_addr,
                                       addr_t* end_addr);

/**
 * @brief Check if an address lies within the kernel .text section bounds.
 *
 * @param vmi The VMI instance.
 * @param addr The address to check if in bounds.
 * @return true if the address is within bounds, false otherwise.
 */
bool is_in_kernel_text(vmi_instance_t vmi, addr_t addr);

/**
 * @brief Log the state of a vCPU.
 * 
 * @param vmi The VMI instance. 
 * @param vcpu_id The vCPU ID.
 * @param kaddr The kernel address of the vCPU structure.
 * @param context The context associated with the event.
 */
void log_vcpu_state(vmi_instance_t vmi, uint32_t vcpu_id, addr_t kaddr,
                    const char* context);

#endif