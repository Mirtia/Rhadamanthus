/**
 * @file network_trace_response.h
 * @brief Response structure and functions for network trace state analysis.
 * @version 0.0
 * @date 2025-01-27
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef NETWORK_TRACE_RESPONSE_H
#define NETWORK_TRACE_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (network_trace_state_response)
 * ─────────────────────────────────────────────
 * {
 *   "state": "NETWORK_TRACE",
 *   "tcp_sockets": {
 *     "protocol": "tcp",
 *     "total": 10,
 *     "sockets": [
 *       {
 *         "local_ip": "127.0.0.1",
 *         "local_port": 8080,
 *         "remote_ip": "0.0.0.0",
 *         "remote_port": 0,
 *         "state": "0A",
 *         "inode": "12345",
 *         "is_suspicious": false
 *       }
 *     ]
 *   },
 *   "netfilter_hooks": {
 *     "total_hooks": 5,
 *     "suspicious_hooks": 0,
 *     "hook_entries": [
 *       {
 *         "protocol": "IPv4",
 *         "hook": 0,
 *         "entry": 0,
 *         "func_address": "0xffffffff81000000",
 *         "priv_address": "0xffffffff81001000",
 *         "is_suspicious": false
 *       }
 *     ]
 *   },
 *   "summary": {
 *     "total_connections": 10,
 *     "suspicious_connections": 0,
 *     "total_hooks": 5,
 *     "suspicious_hooks": 0
 *   }
 * }
 */

/**
 * @brief Information about a network socket connection.
 */
typedef struct network_socket {
  char* local_ip;        ///< Local IP address
  uint16_t local_port;   ///< Local port number
  char* remote_ip;       ///< Remote IP address
  uint16_t remote_port;  ///< Remote port number
  char* state;           ///< Connection state (hex string)
  char* inode;           ///< Socket inode
  bool is_suspicious;    ///< True if connection appears suspicious
} network_socket_t;

/**
 * @brief Information about a netfilter hook entry.
 */
typedef struct netfilter_hook_entry {
  char* protocol;         ///< Protocol (IPv4, IPv6, ARP, Bridge)
  uint32_t hook;          ///< Hook number
  uint32_t entry;         ///< Entry number within hook
  uint64_t func_address;  ///< Hook function address
  uint64_t priv_address;  ///< Hook private data address
  bool is_suspicious;     ///< True if hook appears suspicious
} netfilter_hook_entry_t;

/**
 * @brief Summary information for network trace.
 */
typedef struct network_trace_summary {
  uint32_t total_connections;       ///< Total number of connections found
  uint32_t suspicious_connections;  ///< Number of suspicious connections
  uint32_t total_hooks;             ///< Total number of netfilter hooks
  uint32_t suspicious_hooks;        ///< Number of suspicious hooks
} network_trace_summary_t;

/**
 * @brief State data for network trace analysis.
 */
typedef struct network_trace_state_data {
  GArray* tcp_sockets;              ///< Array of network_socket_t
  GArray* netfilter_hooks;          ///< Array of netfilter_hook_entry_t
  network_trace_summary_t summary;  ///< Summary information
} network_trace_state_data_t;

/**
 * @brief Allocate and initialize a new network trace state data object.
 *
 * @return Pointer to a newly allocated network_trace_state_data_t, or NULL on failure.
 */
network_trace_state_data_t* network_trace_state_data_new(void);

/**
 * @brief Free a network trace state data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void network_trace_state_data_free(network_trace_state_data_t* data);

/**
 * @brief Add a TCP socket connection.
 *
 * @param data The network trace state data object.
 * @param local_ip Local IP address.
 * @param local_port Local port number.
 * @param remote_ip Remote IP address.
 * @param remote_port Remote port number.
 * @param state Connection state (hex string).
 * @param inode Socket inode.
 * @param is_suspicious Whether the connection is suspicious.
 */
void network_trace_state_add_tcp_socket(network_trace_state_data_t* data,
                                        const char* local_ip,
                                        uint16_t local_port,
                                        const char* remote_ip,
                                        uint16_t remote_port, const char* state,
                                        const char* inode, bool is_suspicious);

/**
 * @brief Add a netfilter hook entry.
 *
 * @param data The network trace state data object.
 * @param protocol Protocol name (IPv4, IPv6, ARP, Bridge).
 * @param hook Hook number.
 * @param entry Entry number within hook.
 * @param func_address Hook function address.
 * @param priv_address Hook private data address.
 * @param is_suspicious Whether the hook is suspicious.
 */
void network_trace_state_add_netfilter_hook(network_trace_state_data_t* data,
                                            const char* protocol, uint32_t hook,
                                            uint32_t entry,
                                            uint64_t func_address,
                                            uint64_t priv_address,
                                            bool is_suspicious);

/**
 * @brief Set the summary information.
 *
 * @param data The network trace state data object.
 * @param total_connections Total number of connections.
 * @param suspicious_connections Number of suspicious connections.
 * @param total_hooks Total number of netfilter hooks.
 * @param suspicious_hooks Number of suspicious hooks.
 */
void network_trace_state_set_summary(network_trace_state_data_t* data,
                                     uint32_t total_connections,
                                     uint32_t suspicious_connections,
                                     uint32_t total_hooks,
                                     uint32_t suspicious_hooks);

/**
 * @brief Serialize a network trace state data object to JSON.
 *
 * @param data Pointer to the network trace state data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* network_trace_state_data_to_json(const network_trace_state_data_t* data);

#endif  // NETWORK_TRACE_RESPONSE_H
