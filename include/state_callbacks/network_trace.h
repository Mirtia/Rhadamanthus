/**
 * @file network_trace.h
 * @author Myrsini Gkolemi
 * @brief This file contains the callback function to detect network hooks and suspicious network activities related to kernel-mode rootkits.
 * @version 0.0
 * @date 2025-08-24
 * 
 * @copyright GNU Lesser General Public License v2.1
 */
#ifndef NETWORK_TRACE_H
#define NETWORK_TRACE_H

#include <libvmi/libvmi.h>
#include <stdint.h>

/**
 * @brief Network rootkit detection callback for VMI-based security monitoring
 * 
 * This callback performs comprehensive network level rootkit detection by analyzing
 * kernel networking structures and identifying suspicious network activities that
 * may indicate the presence of kernel-mode rootkits.
 * 
 * * Netfilter hook analysis: Detects unauthorized or excessive netfilter hooks
 *   that rootkits use to filter network traffic visibility
 * * Direct TCP hash table walking: Bypasses normal networking APIs to find
 *   connections hidden from /proc/net/tcp by rootkit manipulation
 * * Suspicious pattern detection: Identifies known rootkit ports and unusual
 *   network patterns commonly used by malicious kernel modules
 * 
 * Known Kernel Rootkit Ports:
 * * Port 666: Reptile rootkit default for port-knocking mechanism
 *
 * @todo: Add more known rootkit ports / backdoors.
 * 
 * @param vmi The VMI instance.
 * @param context User-defined context [unused].
 * @return VMI_SUCCESS on successful inspection, else VMI_FAILURE.
 */
uint32_t state_network_trace_callback(vmi_instance_t vmi, void* context);

#endif  // NETWORK_TRACE_H
