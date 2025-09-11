#include "state_callbacks/responses/process_list_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

process_list_state_data_t* process_list_state_data_new(void) {
  process_list_state_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for process list state data.");
    return NULL;
  }

  data->processes = g_array_new(FALSE, FALSE, sizeof(process_info_t));
  if (!data->processes) {
    process_list_state_data_free(data);
    log_error("Failed to allocate array for process list state data.");
    return NULL;
  }

  return data;
}

void process_list_state_data_free(process_list_state_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL process_list_state_data_t pointer.");
    return;
  }

  if (data->processes) {
    for (guint i = 0; i < data->processes->len; i++) {
      process_info_t* process_info =
          &g_array_index(data->processes, process_info_t, i);
      g_free(process_info->name);
    }
    g_array_free(data->processes, TRUE);
  }

  g_free(data);
}

void process_list_state_set_basic_info(process_list_state_data_t* data,
                                       // NOLINTNEXTLINE
                                       uint32_t page_size, uint32_t count) {
  if (!data)
    return;
  data->page_size = page_size;
  data->count = count;
}

void process_list_state_add_process(process_list_state_data_t* data,
                                    uint32_t pid, const char* name, char state,
                                    uint32_t rss_pages, uint32_t rss_bytes,
                                    uint64_t task_struct_addr,
                                    bool is_kernel_thread,
                                    const process_credentials_t* credentials) {
  if (!data || !data->processes)
    return;

  process_info_t process_info = {
      .pid = pid,
      .name = name ? g_strdup(name) : g_strdup("unknown"),
      .state = state,
      .rss_pages = rss_pages,
      .rss_bytes = rss_bytes,
      .task_struct_addr = task_struct_addr,
      .is_kernel_thread = is_kernel_thread,
      .credentials = credentials ? *credentials : (process_credentials_t){0}};

  g_array_append_val(data->processes, process_info);
}

void process_list_state_set_summary(process_list_state_data_t* data,
                                    // NOLINTNEXTLINE
                                    uint32_t total_processes,
                                    uint32_t user_processes,
                                    uint32_t kernel_threads) {
  if (!data)
    return;
  data->summary.total_processes = total_processes;
  data->summary.user_processes = user_processes;
  data->summary.kernel_threads = kernel_threads;
}

cJSON* process_list_state_data_to_json(const process_list_state_data_t* data) {
  if (!data) {
    log_error("Invalid process_list_state_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for process list state data.");
    return NULL;
  }

  // Basic information
  cJSON_AddNumberToObject(root, "count", (double)data->count);
  cJSON_AddNumberToObject(root, "page_size", (double)data->page_size);

  // Processes array
  cJSON* processes = cJSON_CreateArray();
  if (!processes) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "processes", processes);

  for (guint i = 0; i < data->processes->len; i++) {
    process_info_t* process_info =
        &g_array_index(data->processes, process_info_t, i);

    cJSON* process_obj = cJSON_CreateObject();
    if (!process_obj) {
      cJSON_Delete(root);
      return NULL;
    }

    cJSON_AddNumberToObject(process_obj, "pid", (double)process_info->pid);
    cJSON_AddStringToObject(process_obj, "name", process_info->name);

    // Convert state to string (single character)
    char state_str[2] = {process_info->state, '\0'};
    cJSON_AddStringToObject(process_obj, "state", state_str);

    cJSON_AddNumberToObject(process_obj, "rss_pages",
                            (double)process_info->rss_pages);
    cJSON_AddNumberToObject(process_obj, "rss_bytes",
                            (double)process_info->rss_bytes);
    cjson_add_hex_u64(process_obj, "task_struct_addr",
                      process_info->task_struct_addr);
    cjson_add_bool(process_obj, "is_kernel_thread",
                   process_info->is_kernel_thread);

    // Add credentials for user processes
    if (!process_info->is_kernel_thread) {
      cJSON* credentials = cJSON_CreateObject();
      if (!credentials) {
        cJSON_Delete(root);
        return NULL;
      }
      cJSON_AddItemToObject(process_obj, "credentials", credentials);
      cJSON_AddNumberToObject(credentials, "uid",
                              (double)process_info->credentials.uid);
      cJSON_AddNumberToObject(credentials, "gid",
                              (double)process_info->credentials.gid);
      cJSON_AddNumberToObject(credentials, "euid",
                              (double)process_info->credentials.euid);
      cJSON_AddNumberToObject(credentials, "egid",
                              (double)process_info->credentials.egid);
    }

    cJSON_AddItemToArray(processes, process_obj);
  }

  // Summary information
  cJSON* summary = cJSON_CreateObject();
  if (!summary) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "summary", summary);
  cJSON_AddNumberToObject(summary, "total_processes",
                          (double)data->summary.total_processes);
  cJSON_AddNumberToObject(summary, "user_processes",
                          (double)data->summary.user_processes);
  cJSON_AddNumberToObject(summary, "kernel_threads",
                          (double)data->summary.kernel_threads);

  return root;
}
