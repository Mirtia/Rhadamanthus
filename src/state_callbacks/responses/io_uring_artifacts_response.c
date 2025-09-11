#include "state_callbacks/responses/io_uring_artifacts_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

io_uring_artifacts_state_data_t* io_uring_artifacts_state_data_new(void) {
  io_uring_artifacts_state_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for io_uring artifacts state data.");
    return NULL;
  }

  data->io_uring_instances =
      g_array_new(FALSE, FALSE, sizeof(io_uring_instance_info_t));
  if (!data->io_uring_instances) {
    io_uring_artifacts_state_data_free(data);
    log_error("Failed to allocate array for io_uring artifacts state data.");
    return NULL;
  }

  return data;
}

void io_uring_artifacts_state_data_free(io_uring_artifacts_state_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL io_uring_artifacts_state_data_t pointer.");
    return;
  }

  if (data->io_uring_instances) {
    for (guint i = 0; i < data->io_uring_instances->len; i++) {
      io_uring_instance_info_t* instance =
          &g_array_index(data->io_uring_instances, io_uring_instance_info_t, i);
      g_free(instance->process_name);
    }
    g_array_free(data->io_uring_instances, TRUE);
  }

  g_free(data);
}

void io_uring_artifacts_state_add_instance(
    io_uring_artifacts_state_data_t* data, uint32_t pid,
    const char* process_name, uint64_t io_uring_task_addr,
    uint64_t context_addr, uint64_t rings_addr, uint32_t sq_entries,
    uint32_t cq_entries, bool geometry_sane, bool sq_power_of_two,
    bool cq_power_of_two, bool is_suspicious) {
  if (!data || !data->io_uring_instances)
    return;

  io_uring_instance_info_t instance = {
      .pid = pid,
      .process_name =
          process_name ? g_strdup(process_name) : g_strdup("unknown"),
      .io_uring_task_addr = io_uring_task_addr,
      .context_addr = context_addr,
      .rings_addr = rings_addr,
      .sq_entries = sq_entries,
      .cq_entries = cq_entries,
      .geometry_sane = geometry_sane,
      .sq_power_of_two = sq_power_of_two,
      .cq_power_of_two = cq_power_of_two,
      .is_suspicious = is_suspicious};

  g_array_append_val(data->io_uring_instances, instance);
}

void io_uring_artifacts_state_set_worker_threads(
    io_uring_artifacts_state_data_t* data, uint64_t iou_worker_count,
    uint64_t iou_sqp_count) {
  if (!data)
    return;
  data->worker_threads.iou_worker_count = iou_worker_count;
  data->worker_threads.iou_sqp_count = iou_sqp_count;
}

void io_uring_artifacts_state_set_summary(io_uring_artifacts_state_data_t* data,
                                          uint32_t total_instances,
                                          uint32_t suspicious_instances,
                                          uint64_t total_worker_threads,
                                          uint64_t tasks_scanned) {
  if (!data)
    return;
  data->summary.total_instances = total_instances;
  data->summary.suspicious_instances = suspicious_instances;
  data->summary.total_worker_threads = total_worker_threads;
  data->summary.tasks_scanned = tasks_scanned;
}

cJSON* io_uring_artifacts_state_data_to_json(
    const io_uring_artifacts_state_data_t* data) {
  if (!data) {
    log_error("Invalid io_uring_artifacts_state_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error(
        "Failed to create cJSON object for io_uring artifacts state data.");
    return NULL;
  }

  // io_uring instances array
  cJSON* instances_array = cJSON_CreateArray();
  if (!instances_array) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "io_uring_instances", instances_array);

  for (guint i = 0; i < data->io_uring_instances->len; i++) {
    io_uring_instance_info_t* instance =
        &g_array_index(data->io_uring_instances, io_uring_instance_info_t, i);

    cJSON* instance_obj = cJSON_CreateObject();
    if (!instance_obj) {
      cJSON_Delete(root);
      return NULL;
    }

    cJSON_AddNumberToObject(instance_obj, "pid", (double)instance->pid);
    cJSON_AddStringToObject(instance_obj, "process_name",
                            instance->process_name);
    cjson_add_hex_u64(instance_obj, "io_uring_task_addr",
                      instance->io_uring_task_addr);
    cjson_add_hex_u64(instance_obj, "context_addr", instance->context_addr);
    cjson_add_hex_u64(instance_obj, "rings_addr", instance->rings_addr);
    cJSON_AddNumberToObject(instance_obj, "sq_entries",
                            (double)instance->sq_entries);
    cJSON_AddNumberToObject(instance_obj, "cq_entries",
                            (double)instance->cq_entries);
    cjson_add_bool(instance_obj, "geometry_sane", instance->geometry_sane);
    cjson_add_bool(instance_obj, "sq_power_of_two", instance->sq_power_of_two);
    cjson_add_bool(instance_obj, "cq_power_of_two", instance->cq_power_of_two);
    cjson_add_bool(instance_obj, "is_suspicious", instance->is_suspicious);

    cJSON_AddItemToArray(instances_array, instance_obj);
  }

  // Worker threads section
  cJSON* worker_threads = cJSON_CreateObject();
  if (!worker_threads) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "worker_threads", worker_threads);
  cJSON_AddNumberToObject(worker_threads, "iou_worker_count",
                          (double)data->worker_threads.iou_worker_count);
  cJSON_AddNumberToObject(worker_threads, "iou_sqp_count",
                          (double)data->worker_threads.iou_sqp_count);

  // Summary section
  cJSON* summary = cJSON_CreateObject();
  if (!summary) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "summary", summary);
  cJSON_AddNumberToObject(summary, "total_instances",
                          (double)data->summary.total_instances);
  cJSON_AddNumberToObject(summary, "suspicious_instances",
                          (double)data->summary.suspicious_instances);
  cJSON_AddNumberToObject(summary, "total_worker_threads",
                          (double)data->summary.total_worker_threads);
  cJSON_AddNumberToObject(summary, "tasks_scanned",
                          (double)data->summary.tasks_scanned);

  return root;
}
