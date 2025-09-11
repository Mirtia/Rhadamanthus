#include "state_callbacks/responses/ebpf_activity_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

ebpf_activity_state_data_t* ebpf_activity_state_data_new(void) {
  ebpf_activity_state_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for eBPF activity state data.");
    return NULL;
  }

  data->loaded_programs =
      g_array_new(FALSE, FALSE, sizeof(ebpf_program_info_t));
  if (!data->loaded_programs) {
    ebpf_activity_state_data_free(data);
    log_error("Failed to allocate array for eBPF programs state data.");
    return NULL;
  }

  data->maps = g_array_new(FALSE, FALSE, sizeof(ebpf_map_info_t));
  if (!data->maps) {
    ebpf_activity_state_data_free(data);
    log_error("Failed to allocate array for eBPF maps state data.");
    return NULL;
  }

  data->links = g_array_new(FALSE, FALSE, sizeof(ebpf_link_info_t));
  if (!data->links) {
    ebpf_activity_state_data_free(data);
    log_error("Failed to allocate array for eBPF links state data.");
    return NULL;
  }

  data->attachment_points =
      g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
  if (!data->attachment_points) {
    ebpf_activity_state_data_free(data);
    log_error(
        "Failed to allocate hash table for eBPF attachment points state data.");
    return NULL;
  }

  data->summary.programs_by_type =
      g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
  if (!data->summary.programs_by_type) {
    ebpf_activity_state_data_free(data);
    log_error(
        "Failed to allocate programs by type hash table for eBPF activity "
        "state data.");
    return NULL;
  }

  return data;
}

void ebpf_activity_state_data_free(ebpf_activity_state_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL ebpf_activity_state_data_t pointer.");
    return;
  }

  if (data->loaded_programs) {
    for (guint i = 0; i < data->loaded_programs->len; i++) {
      ebpf_program_info_t* prog =
          &g_array_index(data->loaded_programs, ebpf_program_info_t, i);
      g_free(prog->type);
      g_free(prog->name);
      g_free(prog->attach_type);
      g_free(prog->process_name);
    }
    g_array_free(data->loaded_programs, TRUE);
  }

  if (data->maps) {
    for (guint i = 0; i < data->maps->len; i++) {
      ebpf_map_info_t* map = &g_array_index(data->maps, ebpf_map_info_t, i);
      g_free(map->process_name);
    }
    g_array_free(data->maps, TRUE);
  }

  if (data->links) {
    for (guint i = 0; i < data->links->len; i++) {
      ebpf_link_info_t* link = &g_array_index(data->links, ebpf_link_info_t, i);
      g_free(link->process_name);
    }
    g_array_free(data->links, TRUE);
  }

  if (data->attachment_points) {
    g_hash_table_destroy(data->attachment_points);
  }

  if (data->summary.programs_by_type) {
    g_hash_table_destroy(data->summary.programs_by_type);
  }

  g_free(data);
}

void ebpf_activity_state_add_program(ebpf_activity_state_data_t* data,
                                     uint32_t id, const char* type,
                                     const char* name, const char* attach_type,
                                     uint64_t prog_addr, uint64_t aux_addr,
                                     uint32_t pid, const char* process_name) {
  if (!data || !data->loaded_programs)
    return;

  ebpf_program_info_t program = {
      .id = id,
      .type = type ? g_strdup(type) : g_strdup("unknown"),
      .name = name ? g_strdup(name) : g_strdup("unknown"),
      .attach_type = attach_type ? g_strdup(attach_type) : g_strdup("unknown"),
      .prog_addr = prog_addr,
      .aux_addr = aux_addr,
      .pid = pid,
      .process_name =
          process_name ? g_strdup(process_name) : g_strdup("unknown")};

  g_array_append_val(data->loaded_programs, program);
}

void ebpf_activity_state_add_map(ebpf_activity_state_data_t* data, uint32_t id,
                                 uint64_t map_addr, uint32_t pid,
                                 const char* process_name) {
  if (!data || !data->maps)
    return;

  ebpf_map_info_t map = {.id = id,
                         .map_addr = map_addr,
                         .pid = pid,
                         .process_name = process_name ? g_strdup(process_name)
                                                      : g_strdup("unknown")};

  g_array_append_val(data->maps, map);
}

void ebpf_activity_state_add_link(ebpf_activity_state_data_t* data, uint32_t id,
                                  uint64_t link_addr, uint32_t pid,
                                  const char* process_name) {
  if (!data || !data->links)
    return;

  ebpf_link_info_t link = {.id = id,
                           .link_addr = link_addr,
                           .pid = pid,
                           .process_name = process_name ? g_strdup(process_name)
                                                        : g_strdup("unknown")};

  g_array_append_val(data->links, link);
}

void ebpf_activity_state_add_attachment_point(ebpf_activity_state_data_t* data,
                                              const char* attach_type,
                                              uint32_t program_id) {
  if (!data || !data->attachment_points || !attach_type)
    return;

  GArray* ids = g_hash_table_lookup(data->attachment_points, attach_type);
  if (!ids) {
    ids = g_array_new(FALSE, FALSE, sizeof(uint32_t));
    g_hash_table_insert(data->attachment_points, g_strdup(attach_type), ids);
  }
  g_array_append_val(ids, program_id);
}

void ebpf_activity_state_set_summary(ebpf_activity_state_data_t* data,
                                     uint32_t total_programs,
                                     uint32_t total_maps, uint32_t total_links,
                                     uint32_t total_btf_objects,
                                     uint32_t processes_with_ebpf) {
  if (!data)
    return;
  data->summary.total_programs = total_programs;
  data->summary.total_maps = total_maps;
  data->summary.total_links = total_links;
  data->summary.total_btf_objects = total_btf_objects;
  data->summary.processes_with_ebpf = processes_with_ebpf;
}

cJSON* ebpf_activity_state_data_to_json(
    const ebpf_activity_state_data_t* data) {
  if (!data) {
    log_error("Invalid ebpf_activity_state_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for eBPF activity state data.");
    return NULL;
  }

  // loaded_programs array
  cJSON* programs_array = cJSON_CreateArray();
  if (!programs_array) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "loaded_programs", programs_array);

  for (guint i = 0; i < data->loaded_programs->len; i++) {
    ebpf_program_info_t* prog =
        &g_array_index(data->loaded_programs, ebpf_program_info_t, i);

    cJSON* prog_obj = cJSON_CreateObject();
    if (!prog_obj) {
      cJSON_Delete(root);
      return NULL;
    }

    cJSON_AddNumberToObject(prog_obj, "id", (double)prog->id);
    cJSON_AddStringToObject(prog_obj, "type", prog->type);
    cJSON_AddStringToObject(prog_obj, "name", prog->name);
    cJSON_AddStringToObject(prog_obj, "attach_type", prog->attach_type);
    cjson_add_hex_u64(prog_obj, "prog_addr", prog->prog_addr);
    cjson_add_hex_u64(prog_obj, "aux_addr", prog->aux_addr);
    cJSON_AddNumberToObject(prog_obj, "pid", (double)prog->pid);
    cJSON_AddStringToObject(prog_obj, "process_name", prog->process_name);

    cJSON_AddItemToArray(programs_array, prog_obj);
  }

  // attachment_points object
  cJSON* attachment_points = cJSON_CreateObject();
  if (!attachment_points) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "attachment_points", attachment_points);

  GHashTableIter iter;
  gpointer key, value;
  g_hash_table_iter_init(&iter, data->attachment_points);
  while (g_hash_table_iter_next(&iter, &key, &value)) {
    const char* attach_type = (const char*)key;
    GArray* ids = (GArray*)value;

    cJSON* ids_array = cJSON_CreateArray();
    if (!ids_array) {
      cJSON_Delete(root);
      return NULL;
    }

    for (guint j = 0; j < ids->len; j++) {
      uint32_t id = g_array_index(ids, uint32_t, j);
      cJSON_AddItemToArray(ids_array, cJSON_CreateNumber((double)id));
    }

    cJSON_AddItemToObject(attachment_points, attach_type, ids_array);
  }

  // Summary section
  cJSON* summary = cJSON_CreateObject();
  if (!summary) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "summary", summary);
  cJSON_AddNumberToObject(summary, "total_programs",
                          (double)data->summary.total_programs);
  cJSON_AddNumberToObject(summary, "total_maps",
                          (double)data->summary.total_maps);
  cJSON_AddNumberToObject(summary, "total_links",
                          (double)data->summary.total_links);
  cJSON_AddNumberToObject(summary, "total_btf_objects",
                          (double)data->summary.total_btf_objects);
  cJSON_AddNumberToObject(summary, "processes_with_ebpf",
                          (double)data->summary.processes_with_ebpf);

  // programs_by_type object
  cJSON* programs_by_type = cJSON_CreateObject();
  if (!programs_by_type) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(summary, "programs_by_type", programs_by_type);

  GHashTableIter type_iter;
  gpointer type_key, type_value;
  g_hash_table_iter_init(&type_iter, data->summary.programs_by_type);
  while (g_hash_table_iter_next(&type_iter, &type_key, &type_value)) {
    const char* prog_type = (const char*)type_key;
    uint32_t* count = (uint32_t*)type_value;
    cJSON_AddNumberToObject(programs_by_type, prog_type, (double)*count);
  }

  return root;
}
