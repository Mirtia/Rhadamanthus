#ifndef UTILS_H
#define UTILS_H
#include <libvmi/libvmi.h>

/**
 * @brief Get the kernel text section range object
 * 
 * @param vmi The VMI instance.
 * @param start_addr The output start address of the kernel text section.
 * @param end_addr The output end address of the kernel text section.
 * @return uint32_t VMI_SUCCESS on success, VMI_FAILURE on failure
 */
uint32_t get_kernel_text_section_range(vmi_instance_t vmi, addr_t* start_addr,
                                       addr_t* end_addr);

#endif