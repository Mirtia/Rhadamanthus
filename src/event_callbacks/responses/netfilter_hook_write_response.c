#include "event_callbacks/responses/netfilter_hook_write_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

netfilter_hook_write_data_t* netfilter_hook_write_data_new(
    // NOLINTNEXTLINE
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3,
    uint64_t breakpoint_addr, uint64_t net_ptr, uint64_t ops_ptr,
    uint64_t count, const char* symbol_name) {
  netfilter_hook_write_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for netfilter hook write data.");
    return NULL;
  }

  data->vcpu_id = vcpu_id;
  data->rip = rip;
  data->rsp = rsp;
  data->cr3 = cr3;
  data->breakpoint_addr = breakpoint_addr;
  data->net_ptr = net_ptr;
  data->ops_ptr = ops_ptr;
  data->count = count;

  if (symbol_name) {
    data->symbol_name = g_strdup(symbol_name);
    if (!data->symbol_name) {
      g_free(data);
      log_error("Failed to allocate memory for symbol name.");
      return NULL;
    }
  } else {
    data->symbol_name = NULL;
  }

  return data;
}

void netfilter_hook_write_data_free(netfilter_hook_write_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL netfilter_hook_write_data_t pointer.");
    return;
  }

  if (data->symbol_name) {
    g_free(data->symbol_name);
  }

  g_free(data);
}

cJSON* netfilter_hook_write_data_to_json(
    const netfilter_hook_write_data_t* data) {
  if (!data) {
    log_error("Invalid netfilter_hook_write_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for netfilter hook write data.");
    return NULL;
  }

  // vcpu_id as a JSON number
  cJSON_AddNumberToObject(root, "vcpu_id", (double)data->vcpu_id);

  // Register values
  cJSON* regs = cJSON_CreateObject();
  if (!regs) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "regs", regs);
  cjson_add_hex_u64(regs, "rip", data->rip);
  cjson_add_hex_u64(regs, "rsp", data->rsp);
  cjson_add_hex_u64(regs, "cr3", data->cr3);

  // Netfilter-specific information
  cJSON* netfilter = cJSON_CreateObject();
  if (!netfilter) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "netfilter", netfilter);

  cjson_add_hex_u64(netfilter, "breakpoint_addr", data->breakpoint_addr);

  if (data->symbol_name) {
    cJSON_AddStringToObject(netfilter, "symbol_name", data->symbol_name);
  } else {
    cJSON_AddStringToObject(netfilter, "symbol_name", "unknown");
  }

  // Function arguments
  cJSON* function_args = cJSON_CreateObject();
  if (!function_args) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(netfilter, "function_args", function_args);
  cjson_add_hex_u64(function_args, "net_ptr", data->net_ptr);
  cjson_add_hex_u64(function_args, "ops_ptr", data->ops_ptr);
  cjson_add_hex_u64(function_args, "count", data->count);

  return root;
}