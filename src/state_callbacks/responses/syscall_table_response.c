#include "state_callbacks/responses/syscall_table_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

syscall_table_state_data_t* syscall_table_state_data_new(void) {
  syscall_table_state_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for syscall table state data.");
    return NULL;
  }

  data->syscalls = g_array_new(FALSE, FALSE, sizeof(syscall_info_t));
  if (!data->syscalls) {
    syscall_table_state_data_free(data);
    log_error("Failed to allocate array for syscall table state data.");
    return NULL;
  }

  return data;
}

void syscall_table_state_data_free(syscall_table_state_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL syscall_table_state_data_t pointer.");
    return;
  }

  if (data->syscalls) {
    for (guint i = 0; i < data->syscalls->len; i++) {
      syscall_info_t* syscall_info =
          &g_array_index(data->syscalls, syscall_info_t, i);
      g_free(syscall_info->name);
    }
    g_array_free(data->syscalls, TRUE);
  }

  g_free(data);
}

void syscall_table_state_set_kernel_range(syscall_table_state_data_t* data,
                                          uint64_t kernel_start,
                                          uint64_t kernel_end) {
  if (!data)
    return;
  data->kernel_start = kernel_start;
  data->kernel_end = kernel_end;
}

void syscall_table_state_set_table_info(syscall_table_state_data_t* data,
                                        uint64_t table_addr,
                                        uint32_t total_count) {
  if (!data)
    return;
  data->syscall_table_addr = table_addr;
  data->total_syscalls = total_count;
}

void syscall_table_state_add_syscall(syscall_table_state_data_t* data,
                                     uint32_t index, const char* name,
                                     uint64_t address, bool is_hooked) {
  if (!data || !data->syscalls)
    return;

  syscall_info_t syscall_info = {
      .index = index,
      .name = name ? g_strdup(name) : g_strdup("unknown"),
      .address = address,
      .is_hooked = is_hooked};

  g_array_append_val(data->syscalls, syscall_info);
}

void syscall_table_state_set_summary(syscall_table_state_data_t* data,
                                     uint32_t total_hooked) {
  if (!data)
    return;
  data->total_hooked = total_hooked;
}

cJSON* syscall_table_state_data_to_json(
    const syscall_table_state_data_t* data) {
  if (!data) {
    log_error("Invalid syscall_table_state_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for syscall table state data.");
    return NULL;
  }

  // Kernel range information
  cJSON* kernel_range = cJSON_CreateObject();
  if (!kernel_range) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "kernel_range", kernel_range);
  cjson_add_hex_u64(kernel_range, "start", data->kernel_start);
  cjson_add_hex_u64(kernel_range, "end", data->kernel_end);

  // Syscall table information
  cJSON* syscall_table = cJSON_CreateObject();
  if (!syscall_table) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "syscall_table", syscall_table);
  cjson_add_hex_u64(syscall_table, "address", data->syscall_table_addr);
  cJSON_AddNumberToObject(syscall_table, "total_syscalls",
                          (double)data->total_syscalls);

  // Syscalls array
  cJSON* syscalls = cJSON_CreateArray();
  if (!syscalls) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "syscalls", syscalls);

  for (guint i = 0; i < data->syscalls->len; i++) {
    syscall_info_t* syscall_info =
        &g_array_index(data->syscalls, syscall_info_t, i);

    cJSON* syscall_obj = cJSON_CreateObject();
    if (!syscall_obj) {
      cJSON_Delete(root);
      return NULL;
    }

    cJSON_AddNumberToObject(syscall_obj, "index", (double)syscall_info->index);
    cJSON_AddStringToObject(syscall_obj, "name", syscall_info->name);
    cjson_add_hex_u64(syscall_obj, "address", syscall_info->address);
    cjson_add_bool(syscall_obj, "is_hooked", syscall_info->is_hooked);

    cJSON_AddItemToArray(syscalls, syscall_obj);
  }

  // Summary information
  cJSON* summary = cJSON_CreateObject();
  if (!summary) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "summary", summary);
  cJSON_AddNumberToObject(summary, "total_hooked_syscalls",
                          (double)data->total_hooked);

  double hooked_percentage = 0.0;
  if (data->total_syscalls > 0) {
    hooked_percentage =
        ((double)data->total_hooked / (double)data->total_syscalls) * 100.0;
  }
  cJSON_AddNumberToObject(summary, "hooked_percentage", hooked_percentage);

  return root;
}
