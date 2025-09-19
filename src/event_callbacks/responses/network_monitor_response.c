#include "event_callbacks/responses/network_monitor_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

// Helper function to safely duplicate a string
static char* safe_strdup(const char* str) {
  return str ? g_strdup(str) : NULL;
}

network_connection_info_t* network_connection_info_new(const char* src_ip,
                                                       uint16_t src_port,
                                                       const char* dst_ip,
                                                       uint16_t dst_port) {
  network_connection_info_t* info = g_malloc0(sizeof(*info));
  if (!info) {
    log_error("Failed to allocate memory for network connection info.");
    return NULL;
  }

  info->src_ip = safe_strdup(src_ip);
  info->src_port = src_port;
  info->dst_ip = safe_strdup(dst_ip);
  info->dst_port = dst_port;

  return info;
}

network_binding_info_t* network_binding_info_new(const char* bind_ip,
                                                 uint16_t bind_port) {
  network_binding_info_t* info = g_malloc0(sizeof(*info));
  if (!info) {
    log_error("Failed to allocate memory for network binding info.");
    return NULL;
  }

  info->bind_ip = safe_strdup(bind_ip);
  info->bind_port = bind_port;

  return info;
}

network_function_info_t* network_function_info_new(
    const char* function_type, const char* operation,
    network_connection_info_t* connection, network_binding_info_t* binding,
    uint64_t timeout_ms, uint64_t backlog_size, uint64_t flag_bits,
    const char* shutdown_type) {
  network_function_info_t* info = g_malloc0(sizeof(*info));
  if (!info) {
    log_error("Failed to allocate memory for network function info.");
    return NULL;
  }

  info->function_type = safe_strdup(function_type);
  info->operation = safe_strdup(operation);
  info->connection = connection;
  info->binding = binding;
  info->timeout = timeout_ms;
  info->backlog = backlog_size;
  info->flags = flag_bits;
  info->shutdown_type = safe_strdup(shutdown_type);

  return info;
}

void network_connection_info_free(network_connection_info_t* info) {
  if (!info)
    return;

  g_free(info->src_ip);
  g_free(info->dst_ip);
  g_free(info);
}

void network_binding_info_free(network_binding_info_t* info) {
  if (!info)
    return;

  g_free(info->bind_ip);
  g_free(info);
}

void network_function_info_free(network_function_info_t* info) {
  if (!info)
    return;

  g_free(info->function_type);
  g_free(info->operation);
  g_free(info->shutdown_type);
  network_connection_info_free(info->connection);
  network_binding_info_free(info->binding);
  g_free(info);
}

network_monitor_data_t* network_monitor_data_new(
    // NOLINTNEXTLINE
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3,
    uint64_t breakpoint_addr, uint64_t arg1, uint64_t arg2, uint64_t arg3,
    const char* symbol_name, network_function_info_t* network_info) {
  network_monitor_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for network monitor data.");
    return NULL;
  }

  data->vcpu_id = vcpu_id;
  data->rip = rip;
  data->rsp = rsp;
  data->cr3 = cr3;
  data->breakpoint_addr = breakpoint_addr;
  data->arg1 = arg1;
  data->arg2 = arg2;
  data->arg3 = arg3;

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

  data->network_info = network_info;

  return data;
}

void network_monitor_data_free(network_monitor_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL network_monitor_data_t pointer.");
    return;
  }

  if (data->symbol_name) {
    g_free(data->symbol_name);
  }

  if (data->network_info) {
    network_function_info_free(data->network_info);
  }

  g_free(data);
}

cJSON* network_monitor_data_to_json(const network_monitor_data_t* data) {
  if (!data) {
    log_error("Invalid network_monitor_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for network monitor data.");
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

  // Network monitoring information
  cJSON* network = cJSON_CreateObject();
  if (!network) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "network", network);

  cjson_add_hex_u64(network, "breakpoint_addr", data->breakpoint_addr);

  if (data->symbol_name) {
    cJSON_AddStringToObject(network, "symbol_name", data->symbol_name);
  } else {
    cJSON_AddStringToObject(network, "symbol_name", "unknown");
  }

  // Function arguments
  cJSON* function_args = cJSON_CreateObject();
  if (!function_args) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(network, "function_args", function_args);
  cjson_add_hex_u64(function_args, "arg1", data->arg1);
  cjson_add_hex_u64(function_args, "arg2", data->arg2);
  cjson_add_hex_u64(function_args, "arg3", data->arg3);

  // Detailed network information
  if (data->network_info) {
    cJSON* network_info = cJSON_CreateObject();
    if (!network_info) {
      cJSON_Delete(root);
      return NULL;
    }
    cJSON_AddItemToObject(network, "network_info", network_info);

    // Function type and operation
    if (data->network_info->function_type) {
      cJSON_AddStringToObject(network_info, "function_type",
                              data->network_info->function_type);
    }
    if (data->network_info->operation) {
      cJSON_AddStringToObject(network_info, "operation",
                              data->network_info->operation);
    }

    // Connection information
    if (data->network_info->connection) {
      cJSON* connection = cJSON_CreateObject();
      if (connection) {
        cJSON_AddItemToObject(network_info, "connection", connection);

        if (data->network_info->connection->src_ip) {
          cJSON_AddStringToObject(connection, "src_ip",
                                  data->network_info->connection->src_ip);
        }
        cJSON_AddNumberToObject(connection, "src_port",
                                data->network_info->connection->src_port);

        if (data->network_info->connection->dst_ip) {
          cJSON_AddStringToObject(connection, "dst_ip",
                                  data->network_info->connection->dst_ip);
        }
        cJSON_AddNumberToObject(connection, "dst_port",
                                data->network_info->connection->dst_port);
      }
    }

    // Binding information
    if (data->network_info->binding) {
      cJSON* binding = cJSON_CreateObject();
      if (binding) {
        cJSON_AddItemToObject(network_info, "binding", binding);

        if (data->network_info->binding->bind_ip) {
          cJSON_AddStringToObject(binding, "bind_ip",
                                  data->network_info->binding->bind_ip);
        }
        cJSON_AddNumberToObject(binding, "bind_port",
                                data->network_info->binding->bind_port);
      }
    }

    // Additional function-specific fields
    if (data->network_info->timeout > 0) {
      cJSON_AddNumberToObject(network_info, "timeout",
                              (double)data->network_info->timeout);
    }
    if (data->network_info->backlog > 0) {
      cJSON_AddNumberToObject(network_info, "backlog",
                              (double)data->network_info->backlog);
    }
    if (data->network_info->flags > 0) {
      cJSON_AddNumberToObject(network_info, "flags",
                              (double)data->network_info->flags);
    }
    if (data->network_info->shutdown_type) {
      cJSON_AddStringToObject(network_info, "shutdown_type",
                              data->network_info->shutdown_type);
    }
  }

  return root;
}