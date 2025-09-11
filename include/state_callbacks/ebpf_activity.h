/**
 * @file ebpf_artifacts.h
 * @brief This file contains the callback function to detect eBPF artifacts.
 * @version 0.0
 * @date 2025-09-01
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef EBPF_ARTIFACTS_H
#define EBPF_ARTIFACTS_H

#include <libvmi/events.h>
#include <stdint.h>

/**
 * @brief Minimal ebpf artifacts detection. Checks EBPF acrive programs presence.
 * 1st attempt (LIMITATION): 
 *  * TODO: IDR/XArray registry traversal. This became too complicated, 
 *  too many constants dependning on kernel version.
 *  * Searches patterns associated with known eBPF rootkits.
 *  * Analyze ebpf programs present.
 * @param vmi The VMI instance.
 * @param context The user-defined context [unused].
 * @return uint32_t VMI_SUCCESS on successful inspection else VMI_FAILURE.
 */
uint32_t state_ebpf_activity_callback(vmi_instance_t vmi, void* context);

#endif  // EBPF_ARTIFACTS_H
