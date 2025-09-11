/**
 * @file idt_table.h
 * @brief This file contains the callback function to inspect IDT entries and log handlers outside kernel text.
 * @version 0.0
 * @date 2025-08-10
 * 
 * @copyright GNU Lesser General Public License v2.1
 * @remark The implementation of this file is closely replicating the behavior of idt-check by https://github.com/tianweiz07/Cloud_Integrity 
 * (https://github.com/tianweiz07/Cloud_Integrity/blob/master/src/idt-check.c)
 */
#ifndef IDT_TABLE_H
#define IDT_TABLE_H

#include <libvmi/libvmi.h>
#include <stdint.h>

/**
 * @brief Callback that inspects IDT entries and flags handlers outside kernel text.
 *
 * The function resolves `_stext` and `_etext` to bound the expected kernel text region,
 * reads the IDTR base of vCPU 0, loads vector names from disk, walks all 256 vectors,
 * and logs any named handlers whose addresses fall outside `[_stext, _etext]`.
 *
 * @param vmi      The LibVMI instance.
 * @param context  User-defined context [unused].
 * @return VMI_SUCCESS on successful inspection else VMI_FAILURE.
 */
uint32_t state_idt_table_callback(vmi_instance_t vmi, void* context);

#endif  // IDT_TABLE_H
