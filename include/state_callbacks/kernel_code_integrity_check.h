/**
 * @file kernel_code_integrity_check.h
 * @author Myrsini Gkolemi  
 * @brief This file contains the callback function to compare the kernel's .text section digest with a clear snapshot's .text section digest.
 * @version 0.0
 * @date 2025-08-24
 * 
 * @copyright GNU Lesser General Public License v2.1
 */

#ifndef KERNEL_CODE_INTEGRITY_CHECK_H
#define KERNEL_CODE_INTEGRITY_CHECK_H

#include <libvmi/libvmi.h>
#include <stdint.h>

uint32_t state_kernel_code_integrity_check_callback(vmi_instance_t vmi,
                                                    void* context);

#endif  // KERNEL_CODE_INTEGRITY_CHECK_H
