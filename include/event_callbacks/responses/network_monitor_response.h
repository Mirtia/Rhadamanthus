/**
 * @file network_monitor_response.h
 * @brief Response structure and functions for comprehensive network monitoring events. 
 * @version 0.0
 * @date 2025-09-11
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#ifndef NETWORK_MONITOR_RESPONSE_H
#define NETWORK_MONITOR_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (network_monitor_response)
 * ─────────────────────────────────────────────
 * {
 *   "event": "NETWORK_MONITOR",
 *   "vcpu_id": 0,
 *   "regs": {
 *     "rip": "0xfffff80000010234",
 *     "rsp": "0xfffff8000010ff00",
 *     "cr3": "0x0000000123456000"
 *   },
 *   "network": {
 *     "breakpoint_addr": "0xfffff80000234567",
 *     "symbol_name": "sock_create",
 *     "function_args": {
 *       "family": "0x0000000000000002",
 *       "type": "0x0000000000000001",
 *       "protocol": "0x0000000000000006"
 *     }
 *   }
 * }
 */

/**
 * @brief Network connection information extracted from socket structures.
 */
typedef struct network_connection_info {
  char* src_ip;       ///< Source IP address (e.g., "192.168.1.100").
  uint16_t src_port;  ///< Source port number.
  char* dst_ip;       ///< Destination IP address (e.g., "10.0.0.5").
  uint16_t dst_port;  ///< Destination port number.
} network_connection_info_t;

/**
 * @brief Network binding information extracted from socket structures.
 */
typedef struct network_binding_info {
  char* bind_ip;       ///< IP address being bound to (e.g., "0.0.0.0").
  uint16_t bind_port;  ///< Port being bound to.
} network_binding_info_t;

/**
 * @brief Network function specific information.
 */
typedef struct network_function_info {
  char*
      function_type;  ///< Type of network function (e.g., "TCP_CONNECT", "UDP_BIND").
  char*
      operation;  ///< Description of operation (e.g., "connection establishment").

  // Connection information (for tcp_connect, tcp_close, tcp_shutdown, udp_connect)
  network_connection_info_t* connection;

  // Binding information (for inet_bind, udp_bind, tcp_accept)
  network_binding_info_t* binding;

  // Additional function-specific fields
  uint64_t timeout;  ///< Timeout value (for tcp_close).
  uint64_t backlog;  ///< Backlog value (for inet_listen).
  uint64_t flags;    ///< Flags value (for various functions).
  char*
      shutdown_type;  ///< Shutdown type (for tcp_shutdown: "RD", "WR", "RDWR").
} network_function_info_t;

/**
 * @brief Event payload for comprehensive network monitoring.
 */
typedef struct network_monitor_data {
  uint32_t vcpu_id;  ///< Identifier of the vCPU that triggered the event.
  uint64_t rip;      ///< Instruction pointer (RIP) at the time of the event.
  uint64_t rsp;      ///< Stack pointer (RSP) at the time of the event.
  uint64_t cr3;      ///< CR3 register value at the time of the event.
  uint64_t breakpoint_addr;  ///< Address where the breakpoint was triggered.
  uint64_t arg1;      ///< RDI register value (function-specific argument).
  uint64_t arg2;      ///< RSI register value (function-specific argument).
  uint64_t arg3;      ///< RDX register value (function-specific argument).
  char* symbol_name;  ///< Name of the symbol/function being called.
  network_function_info_t*
      network_info;  ///< Detailed network function information.
} network_monitor_data_t;

/**
 * @brief Allocate and initialize a new network monitor data object.
 *
 * @param vcpu_id The vCPU identifier.
 * @param rip The RIP register value.
 * @param rsp The RSP register value.
 * @param cr3 The CR3 register value.
 * @param breakpoint_addr The address where the breakpoint was triggered.
 * @param arg1 The RDI register value (function-specific argument).
 * @param arg2 The RSI register value (function-specific argument).
 * @param arg3 The RDX register value (function-specific argument).
 * @param symbol_name The symbol name (may be NULL).
 * @param network_info Detailed network function information (may be NULL).
 * @return Pointer to a newly allocated network_monitor_data_t, or NULL on failure.
 */
network_monitor_data_t* network_monitor_data_new(
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3,
    uint64_t breakpoint_addr, uint64_t arg1, uint64_t arg2, uint64_t arg3,
    const char* symbol_name, network_function_info_t* network_info);

/**
 * @brief Create a new network connection info structure.
 *
 * @param src_ip Source IP address (may be NULL).
 * @param src_port Source port number.
 * @param dst_ip Destination IP address (may be NULL).
 * @param dst_port Destination port number.
 * @return Pointer to newly allocated network_connection_info_t, or NULL on failure.
 */
network_connection_info_t* network_connection_info_new(const char* src_ip,
                                                       uint16_t src_port,
                                                       const char* dst_ip,
                                                       uint16_t dst_port);

/**
 * @brief Create a new network binding info structure.
 *
 * @param bind_ip IP address being bound to (may be NULL).
 * @param bind_port Port being bound to.
 * @return Pointer to newly allocated network_binding_info_t, or NULL on failure.
 */
network_binding_info_t* network_binding_info_new(const char* bind_ip,
                                                 uint16_t bind_port);

/**
 * @brief Create a new network function info structure.
 *
 * @param function_type Type of network function (may be NULL).
 * @param operation Description of operation (may be NULL).
 * @param connection Connection information (may be NULL).
 * @param binding Binding information (may be NULL).
 * @param timeout Timeout value (for tcp_close).
 * @param backlog Backlog value (for inet_listen).
 * @param flags Flags value (for various functions).
 * @param shutdown_type Shutdown type (may be NULL).
 * @return Pointer to newly allocated network_function_info_t, or NULL on failure.
 */
network_function_info_t* network_function_info_new(
    const char* function_type, const char* operation,
    network_connection_info_t* connection, network_binding_info_t* binding,
    uint64_t timeout_ms, uint64_t backlog_size, uint64_t flag_bits,
    const char* shutdown_type);

/**
 * @brief Free a network connection info structure.
 *
 * @param info Pointer to the structure to free (may be NULL).
 */
void network_connection_info_free(network_connection_info_t* info);

/**
 * @brief Free a network binding info structure.
 *
 * @param info Pointer to the structure to free (may be NULL).
 */
void network_binding_info_free(network_binding_info_t* info);

/**
 * @brief Free a network function info structure.
 *
 * @param info Pointer to the structure to free (may be NULL).
 */
void network_function_info_free(network_function_info_t* info);

/**
 * @brief Free a network monitor data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void network_monitor_data_free(network_monitor_data_t* data);

/**
 * @brief Serialize a network monitor data object to JSON.
 *
 * @param data Pointer to the network monitor data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* network_monitor_data_to_json(const network_monitor_data_t* data);

#endif  // NETWORK_MONITOR_RESPONSE_H