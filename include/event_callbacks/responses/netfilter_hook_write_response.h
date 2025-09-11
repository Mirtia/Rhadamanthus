/**
 * @file netfilter_hook_write_response.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2025-09-11
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#ifndef NETFILTER_HOOK_WRITE_RESPONSE_H
#define NETFILTER_HOOK_WRITE_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (netfilter_hook_write_response)
 * ─────────────────────────────────────────────
 * {
 *   "event": "NETFILTER_HOOK_WRITE",
 *   "vcpu_id": 0,
 *   "regs": {
 *     "rip": "0xfffff80000010234",
 *     "rsp": "0xfffff8000010ff00",
 *     "cr3": "0x0000000123456000"
 *   },
 *   "netfilter": {
 *     "breakpoint_addr": "0xfffff80000234567",
 *     "symbol_name": "nf_register_net_hook",
 *     "function_args": {
 *       "net_ptr": "0xffff888012345678",
 *       "ops_ptr": "0xffff888087654321",
 *       "count": "0x0000000000000001"
 *     }
 *   }
 * }
 */

/**
 * @brief Event payload for a netfilter hook write.
 */
typedef struct netfilter_hook_write_data {
  uint32_t vcpu_id;  ///< Identifier of the vCPU that triggered the event.
  uint64_t rip;      ///< Instruction pointer (RIP) at the time of the event.
  uint64_t rsp;      ///< Stack pointer (RSP) at the time of the event.
  uint64_t cr3;      ///< CR3 register value at the time of the event.
  uint64_t breakpoint_addr;  ///< Address where the breakpoint was triggered.
  uint64_t net_ptr;          ///< RDI register value (struct net *net).
  uint64_t ops_ptr;   ///< RSI register value (const struct nf_hook_ops *ops).
  uint64_t count;     ///< RDX register value (size_t n).
  char* symbol_name;  ///< Name of the symbol/function being called.
} netfilter_hook_write_data_t;

/**
 * @brief Allocate and initialize a new netfilter hook write data object.
 *
 * @param vcpu_id The vCPU identifier.
 * @param rip The RIP register value.
 * @param rsp The RSP register value.
 * @param cr3 The CR3 register value.
 * @param breakpoint_addr The address where the breakpoint was triggered.
 * @param net_ptr The RDI register value (struct net *).
 * @param ops_ptr The RSI register value (struct nf_hook_ops *).
 * @param count The RDX register value (size_t n).
 * @param symbol_name The symbol name (may be NULL).
 * @return Pointer to a newly allocated netfilter_hook_write_data_t, or NULL on failure.
 */
netfilter_hook_write_data_t* netfilter_hook_write_data_new(
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3,
    uint64_t breakpoint_addr, uint64_t net_ptr, uint64_t ops_ptr,
    uint64_t count, const char* symbol_name);

/**
 * @brief Free a netfilter hook write data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void netfilter_hook_write_data_free(netfilter_hook_write_data_t* data);

/**
 * @brief Serialize a netfilter hook write data object to JSON.
 *
 * @param data Pointer to the netfilter hook write data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* netfilter_hook_write_data_to_json(
    const netfilter_hook_write_data_t* data);

#endif  // NETFILTER_HOOK_WRITE_RESPONSE_H