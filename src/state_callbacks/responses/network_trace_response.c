#include "state_callbacks/responses/network_trace_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

network_trace_state_data_t* network_trace_state_data_new(void) {
  network_trace_state_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for network trace state data.");
    return NULL;
  }

  data->tcp_sockets = g_array_new(FALSE, FALSE, sizeof(network_socket_t));
  data->netfilter_hooks =
      g_array_new(FALSE, FALSE, sizeof(netfilter_hook_entry_t));

  if (!data->tcp_sockets || !data->netfilter_hooks) {
    network_trace_state_data_free(data);
    log_error("Failed to allocate arrays for network trace state data.");
    return NULL;
  }

  return data;
}

void network_trace_state_data_free(network_trace_state_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL network_trace_state_data_t pointer.");
    return;
  }

  if (data->tcp_sockets) {
    for (guint i = 0; i < data->tcp_sockets->len; i++) {
      network_socket_t* socket =
          &g_array_index(data->tcp_sockets, network_socket_t, i);
      g_free(socket->local_ip);
      g_free(socket->remote_ip);
      g_free(socket->state);
      g_free(socket->inode);
    }
    g_array_free(data->tcp_sockets, TRUE);
  }

  if (data->netfilter_hooks) {
    for (guint i = 0; i < data->netfilter_hooks->len; i++) {
      netfilter_hook_entry_t* hook =
          &g_array_index(data->netfilter_hooks, netfilter_hook_entry_t, i);
      g_free(hook->protocol);
    }
    g_array_free(data->netfilter_hooks, TRUE);
  }

  g_free(data);
}

void network_trace_state_add_tcp_socket(network_trace_state_data_t* data,
                                        const char* local_ip,
                                        uint16_t local_port,
                                        const char* remote_ip,
                                        uint16_t remote_port, const char* state,
                                        const char* inode, bool is_suspicious) {
  if (!data || !data->tcp_sockets)
    return;

  network_socket_t socket = {
      .local_ip = local_ip ? g_strdup(local_ip) : g_strdup("0.0.0.0"),
      .local_port = local_port,
      .remote_ip = remote_ip ? g_strdup(remote_ip) : g_strdup("0.0.0.0"),
      .remote_port = remote_port,
      .state = state ? g_strdup(state) : g_strdup("00"),
      .inode = inode ? g_strdup(inode) : g_strdup("0"),
      .is_suspicious = is_suspicious};

  g_array_append_val(data->tcp_sockets, socket);
}

void network_trace_state_add_netfilter_hook(network_trace_state_data_t* data,
                                            const char* protocol, uint32_t hook,
                                            uint32_t entry,
                                            uint64_t func_address,
                                            uint64_t priv_address,
                                            bool is_suspicious) {
  if (!data || !data->netfilter_hooks)
    return;

  netfilter_hook_entry_t hook_entry = {
      .protocol = protocol ? g_strdup(protocol) : g_strdup("UNKNOWN"),
      .hook = hook,
      .entry = entry,
      .func_address = func_address,
      .priv_address = priv_address,
      .is_suspicious = is_suspicious};

  g_array_append_val(data->netfilter_hooks, hook_entry);
}

void network_trace_state_set_summary(network_trace_state_data_t* data,
                                     uint32_t total_connections,
                                     uint32_t suspicious_connections,
                                     uint32_t total_hooks,
                                     uint32_t suspicious_hooks) {
  if (!data)
    return;
  data->summary.total_connections = total_connections;
  data->summary.suspicious_connections = suspicious_connections;
  data->summary.total_hooks = total_hooks;
  data->summary.suspicious_hooks = suspicious_hooks;
}

cJSON* network_trace_state_data_to_json(
    const network_trace_state_data_t* data) {
  if (!data) {
    log_error("Invalid network_trace_state_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for network trace state data.");
    return NULL;
  }

  // TCP sockets section
  cJSON* tcp_sockets = cJSON_CreateObject();
  if (!tcp_sockets) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "tcp_sockets", tcp_sockets);
  cJSON_AddStringToObject(tcp_sockets, "protocol", "tcp");
  cJSON_AddNumberToObject(tcp_sockets, "total", (double)data->tcp_sockets->len);

  cJSON* sockets_array = cJSON_CreateArray();
  if (!sockets_array) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(tcp_sockets, "sockets", sockets_array);

  for (guint i = 0; i < data->tcp_sockets->len; i++) {
    network_socket_t* socket =
        &g_array_index(data->tcp_sockets, network_socket_t, i);

    cJSON* socket_obj = cJSON_CreateObject();
    if (!socket_obj) {
      cJSON_Delete(root);
      return NULL;
    }

    cJSON_AddStringToObject(socket_obj, "local_ip", socket->local_ip);
    cJSON_AddNumberToObject(socket_obj, "local_port",
                            (double)socket->local_port);
    cJSON_AddStringToObject(socket_obj, "remote_ip", socket->remote_ip);
    cJSON_AddNumberToObject(socket_obj, "remote_port",
                            (double)socket->remote_port);
    cJSON_AddStringToObject(socket_obj, "state", socket->state);
    cJSON_AddStringToObject(socket_obj, "inode", socket->inode);
    cjson_add_bool(socket_obj, "is_suspicious", socket->is_suspicious);

    cJSON_AddItemToArray(sockets_array, socket_obj);
  }

  // Netfilter hooks section
  cJSON* netfilter_hooks = cJSON_CreateObject();
  if (!netfilter_hooks) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "netfilter_hooks", netfilter_hooks);
  cJSON_AddNumberToObject(netfilter_hooks, "total_hooks",
                          (double)data->netfilter_hooks->len);
  cJSON_AddNumberToObject(netfilter_hooks, "suspicious_hooks",
                          (double)data->summary.suspicious_hooks);

  cJSON* hooks_array = cJSON_CreateArray();
  if (!hooks_array) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(netfilter_hooks, "hook_entries", hooks_array);

  for (guint i = 0; i < data->netfilter_hooks->len; i++) {
    netfilter_hook_entry_t* hook =
        &g_array_index(data->netfilter_hooks, netfilter_hook_entry_t, i);

    cJSON* hook_obj = cJSON_CreateObject();
    if (!hook_obj) {
      cJSON_Delete(root);
      return NULL;
    }

    cJSON_AddStringToObject(hook_obj, "protocol", hook->protocol);
    cJSON_AddNumberToObject(hook_obj, "hook", (double)hook->hook);
    cJSON_AddNumberToObject(hook_obj, "entry", (double)hook->entry);
    cjson_add_hex_u64(hook_obj, "func_address", hook->func_address);
    cjson_add_hex_u64(hook_obj, "priv_address", hook->priv_address);
    cjson_add_bool(hook_obj, "is_suspicious", hook->is_suspicious);

    cJSON_AddItemToArray(hooks_array, hook_obj);
  }

  // Summary section
  cJSON* summary = cJSON_CreateObject();
  if (!summary) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "summary", summary);
  cJSON_AddNumberToObject(summary, "total_connections",
                          (double)data->summary.total_connections);
  cJSON_AddNumberToObject(summary, "suspicious_connections",
                          (double)data->summary.suspicious_connections);
  cJSON_AddNumberToObject(summary, "total_hooks",
                          (double)data->summary.total_hooks);
  cJSON_AddNumberToObject(summary, "suspicious_hooks",
                          (double)data->summary.suspicious_hooks);

  return root;
}
