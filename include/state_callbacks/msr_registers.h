/**
 * @file msr_registers.h
 * @author Myrsini Gkolemi
 * @brief Inspect if MSR register dispatcher is modified.
 * @version 0.0
 * @date 2025-08-21
 * 
 * @copyright GNU Lesser General Public License v2.1
 */
#ifndef MSR_REGISTERS_H
#define MSR_REGISTERS_H

#include <libvmi/libvmi.h>
#include <stdint.h>

/**
 * @brief Callback function to check state of MSR registers.
 * 
 * @param vmi  The VMI instance to use for accessing memory.
 * @param context User-defined context [unused].
 * @return uint32_t VMI_SUCCESS on successful inspection else VMI_FAILURE.
 * @note See https://vvdveen.com/data/lstar.txt and https://github.com/RouNNdeL/anti-rootkit-lkm?tab=readme-ov-file#msr-lstar .
 */
uint32_t state_msr_registers_callback(vmi_instance_t vmi, void* context);

#endif  // MSR_REGISTERS_H
