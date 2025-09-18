/**
 * @file network_trace.h
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
 * @brief Network trace state callback. Detects established TCP connections only!
 * 
 * @details This callback walks the kernel's TCP established connections hash table
 * to find active TCP connections. It does NOT include:
 * * Listening sockets (TCP_LISTEN state)
 * * UDP connections
 * * Unix domain sockets
 * 
 * This is intentional to provide a focused view of active established
 * TCP connections that may indicate suspicious network activity.
 * @note This is a direct example of wrong assumptions. The structure for established connections is not the same as
 * listening sockets or UDP sockets. Established TCP connections are stored in the ehash (established hash table)
 * while listening sockets are stored in lhash2 (listening hash table) and UDP sockets have their own hash table.
 * See:
 * * Linux kernel source code: https://elixir.bootlin.com/linux/v5.15.139/source/net/ipv4/tcp_ipv4.c
 * * Inet hashtables header: https://elixir.bootlin.com/linux/v5.15.139/source/include/net/inet_hashtables.h
 * * Network internals book: https://www.oreilly.com/library/view/understanding-linux-network/0596002556/
 * * Linux kernel networking documentation: https://www.kernel.org/doc/html/latest/networking/
 * Since this callback became too complicated, we try to go for event-based detection instead. And try to monitor
 * specific syscall invocations.
 * 
 * @param vmi The VMI instance.
 * @param context The event handler context.
 * @return uint32_t VMI_SUCCESS on success, error code on failure.
 */
uint32_t state_network_trace_callback(vmi_instance_t vmi, void* context);

#endif  // NETWORK_TRACE_H
