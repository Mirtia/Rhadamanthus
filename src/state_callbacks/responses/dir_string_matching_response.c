#include "state_callbacks/responses/dir_string_matching_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

dir_string_matching_state_data_t* dir_string_matching_state_data_new(void) {
  dir_string_matching_state_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for directory string matching state data.");
    return NULL;
  }

  data->matches = g_array_new(FALSE, FALSE, sizeof(dir_match_info_t));
  if (!data->matches) {
    dir_string_matching_state_data_free(data);
    log_error("Failed to allocate array for directory string matching state data.");
    return NULL;
  }

  return data;
}

void dir_string_matching_state_data_free(dir_string_matching_state_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL dir_string_matching_state_data_t pointer.");
    return;
  }

  g_free(data->input_file);

  if (data->matches) {
    for (guint i = 0; i < data->matches->len; i++) {
      dir_match_info_t* match = &g_array_index(data->matches, dir_match_info_t, i);
      g_free(match->path);
      g_free(match->type);
      g_free(match->permissions);
      g_free(match->owner);
      g_free(match->group);
      g_free(match->last_modified);
    }
    g_array_free(data->matches, TRUE);
  }

  g_free(data);
}

void dir_string_matching_state_set_input_file(dir_string_matching_state_data_t* data,
                                             const char* input_file) {
  if (!data)
    return;
  
  g_free(data->input_file);
  data->input_file = input_file ? g_strdup(input_file) : NULL;
}

void dir_string_matching_state_add_match(dir_string_matching_state_data_t* data,
                                        const char* path, bool exists,
                                        const char* type, const char* permissions,
                                        int64_t size, const char* owner,
                                        const char* group, const char* last_modified) {
  if (!data || !data->matches)
    return;

  dir_match_info_t match = {
      .path = path ? g_strdup(path) : g_strdup(""),
      .exists = exists,
      .type = type ? g_strdup(type) : g_strdup("unknown"),
      .permissions = permissions ? g_strdup(permissions) : NULL,
      .size = size,
      .owner = owner ? g_strdup(owner) : NULL,
      .group = group ? g_strdup(group) : NULL,
      .last_modified = last_modified ? g_strdup(last_modified) : NULL};

  g_array_append_val(data->matches, match);
}

void dir_string_matching_state_set_summary(dir_string_matching_state_data_t* data,
                                          uint32_t total_paths,
                                          uint32_t existing_paths,
                                          uint32_t missing_paths,
                                          uint32_t files_found,
                                          uint32_t directories_found,
                                          uint32_t symlinks_found,
                                          uint32_t other_types) {
  if (!data)
    return;
  
  data->summary.total_paths = total_paths;
  data->summary.existing_paths = existing_paths;
  data->summary.missing_paths = missing_paths;
  data->summary.files_found = files_found;
  data->summary.directories_found = directories_found;
  data->summary.symlinks_found = symlinks_found;
  data->summary.other_types = other_types;
}

cJSON* dir_string_matching_state_data_to_json(const dir_string_matching_state_data_t* data) {
  if (!data) {
    log_error("Invalid dir_string_matching_state_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for directory string matching state data.");
    return NULL;
  }

  // input_file
  if (data->input_file) {
    cJSON_AddStringToObject(root, "input_file", data->input_file);
  } else {
    cJSON_AddNullToObject(root, "input_file");
  }

  // matches array
  cJSON* matches_array = cJSON_CreateArray();
  if (!matches_array) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "matches", matches_array);

  for (guint i = 0; i < data->matches->len; i++) {
    dir_match_info_t* match = &g_array_index(data->matches, dir_match_info_t, i);

    cJSON* match_obj = cJSON_CreateObject();
    if (!match_obj) {
      cJSON_Delete(root);
      return NULL;
    }

    cJSON_AddStringToObject(match_obj, "path", match->path);
    cJSON_AddBoolToObject(match_obj, "exists", match->exists);
    cJSON_AddStringToObject(match_obj, "type", match->type);
    
    if (match->permissions) {
      cJSON_AddStringToObject(match_obj, "permissions", match->permissions);
    } else {
      cJSON_AddNullToObject(match_obj, "permissions");
    }
    
    if (match->size >= 0) {
      cJSON_AddNumberToObject(match_obj, "size", (double)match->size);
    } else {
      cJSON_AddNullToObject(match_obj, "size");
    }
    
    if (match->owner) {
      cJSON_AddStringToObject(match_obj, "owner", match->owner);
    } else {
      cJSON_AddNullToObject(match_obj, "owner");
    }
    
    if (match->group) {
      cJSON_AddStringToObject(match_obj, "group", match->group);
    } else {
      cJSON_AddNullToObject(match_obj, "group");
    }
    
    if (match->last_modified) {
      cJSON_AddStringToObject(match_obj, "last_modified", match->last_modified);
    } else {
      cJSON_AddNullToObject(match_obj, "last_modified");
    }

    cJSON_AddItemToArray(matches_array, match_obj);
  }

  // Summary section
  cJSON* summary = cJSON_CreateObject();
  if (!summary) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "summary", summary);
  
  cJSON_AddNumberToObject(summary, "total_paths", (double)data->summary.total_paths);
  cJSON_AddNumberToObject(summary, "existing_paths", (double)data->summary.existing_paths);
  cJSON_AddNumberToObject(summary, "missing_paths", (double)data->summary.missing_paths);
  cJSON_AddNumberToObject(summary, "files_found", (double)data->summary.files_found);
  cJSON_AddNumberToObject(summary, "directories_found", (double)data->summary.directories_found);
  cJSON_AddNumberToObject(summary, "symlinks_found", (double)data->summary.symlinks_found);
  cJSON_AddNumberToObject(summary, "other_types", (double)data->summary.other_types);

  return root;
}
