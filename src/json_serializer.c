#include "json_serializer.h"
#include <log.h>
#include "event_callbacks/responses/cr0_write_response.h"
#include "event_handler.h"

// Global serializer for event callback access
static json_serializer_t* g_serializer = NULL;

static int write_response_to_individual_file(json_serializer_t* serializer,
                                             response_item_t* item) {
  if (!serializer || !item) {
    log_error("Invalid arguments to write_response_to_individual_file");
    return -1;
  }

  // Create directory if it doesn't exist
  if (g_mkdir_with_parents(JSON_LOG_OUTPUT_DIR, 0755) == -1 &&
      errno != EEXIST) {
    log_error("Failed to create directory %s: %s", JSON_LOG_OUTPUT_DIR,
              strerror(errno));
    return -1;
  }
  // Create filename: cr0_write_1694123456789.jsonx
  char* filename = g_strdup_printf("%s/%s_%lu.json", JSON_LOG_OUTPUT_DIR,
                                   item->event_name, item->timestamp_us);

  FILE* file = fopen(filename, "w");
  if (!file) {
    log_error("Failed to create JSON file %s: %s", filename, strerror(errno));
    g_free(filename);
    return -1;
  }

  cJSON* json = response_to_json(item->response_data);
  if (!json) {
    log_error("Failed to convert response to JSON");
    (void)fclose(file);
    g_free(filename);
    return -1;
  }

  char* json_string = cJSON_Print(json);
  if (!json_string) {
    log_error("Failed to serialize JSON");
    cJSON_Delete(json);
    (void)fclose(file);
    g_free(filename);
    return -1;
  }

  // Write JSON to file
  (void)fprintf(file, "%s\n", json_string);

  (void)fclose(file);
  cJSON_Delete(json);
  free(json_string);
  g_free(filename);

  log_debug("Wrote JSON response to: %s_%lu.json", item->event_name,
            item->timestamp_us);
  return 0;
}

json_serializer_t* json_serializer_new() {
  json_serializer_t* serializer = g_malloc0(sizeof(json_serializer_t));
  if (!serializer) {
    log_error("Failed to allocate JSON serializer");
    return NULL;
  }

  serializer->queue =
      g_async_queue_new_full((GDestroyNotify)response_item_free);
  if (!serializer->queue) {
    g_free(serializer);
    return NULL;
  }

  serializer->flush_interval_ms = 5000;

  serializer->total_queued = 0;
  serializer->total_written = 0;
  serializer->total_errors = 0;

  log_info("Created JSON serializer");
  return serializer;
}

void json_serializer_free(json_serializer_t* serializer) {
  if (!serializer) {
    log_warn("Attempted to free NULL JSON serializer");
    return;
  }

  if (serializer->queue) {
    g_async_queue_unref(serializer->queue);
  }

  g_free(serializer);
}

void json_serializer_get_stats(json_serializer_t* serializer,
                               // NOLINTNEXTLINE
                               uint64_t* total_queued, uint64_t* total_written,
                               uint64_t* total_errors) {
  if (!serializer) {
    log_warn("Invalid JSON serializer pointer");
    return;
  }

  if (total_queued)
    *total_queued = serializer->total_queued;
  if (total_written)
    *total_written = serializer->total_written;
  if (total_errors)
    *total_errors = serializer->total_errors;
}

void json_serializer_set_global(json_serializer_t* serializer) {
  g_serializer = serializer;
  if (serializer) {
    log_debug("Set global JSON serializer");
  } else {
    log_debug("Cleared global JSON serializer");
  }
}

json_serializer_t* json_serializer_get_global(void) {
  return g_serializer;
}

int json_serializer_queue_global(const char* event_name,
                                 struct response* response_data) {
  if (!g_serializer) {
    log_debug("No global JSON serializer available, skipping response");
    return -1;
  }

  return json_serializer_queue_response(g_serializer, event_name,
                                        response_data);
}

bool json_serializer_is_global_initialized(void) {
  return g_serializer != NULL;
}

int json_serializer_queue_response(json_serializer_t* serializer,
                                   const char* event_name,
                                   struct response* response_data) {
  if (!serializer) {
    log_error("Invalid JSON serializer pointer");
    return -1;
  }

  if (!event_name || !response_data) {
    log_error("Invalid arguments to queue response");
    return -1;
  }

  response_item_t* item = response_item_new(event_name, response_data);
  if (!item) {
    log_error("Failed to create response item");
    return -1;
  }

  g_async_queue_push(serializer->queue, item);
  serializer->total_queued++;

  return 0;
}

int json_serializer_queue_length(json_serializer_t* serializer) {
  if (!serializer || !serializer->queue) {
    return -1;
  }
  return g_async_queue_length(serializer->queue);
}

response_item_t* response_item_new(const char* event_name,
                                   struct response* response_data) {
  if (!event_name || !response_data) {
    log_warn("Invalid arguments to create response item");
    return NULL;
  }

  response_item_t* item = g_malloc0(sizeof(response_item_t));
  if (!item) {
    return NULL;
  }

  item->event_name = g_strdup(event_name);
  item->response_data = response_data;
  // microseconds
  item->timestamp_us = g_get_monotonic_time();

  return item;
}

void response_item_free(response_item_t* item) {
  if (!item) {
    return;  // Don't log warning for NULL - normal in cleanup
  }

  g_free(item->event_name);

  if (item->response_data) {
    if (item->response_data->timestamp) {
      g_free((void*)item->response_data->timestamp);
    }
    if (item->response_data->metadata) {
      g_free(item->response_data->metadata);
    }
    // Note: response_data->data points to user structures that should be
    // managed by their specific cleanup functions.
    if (item->response_data->error) {
      g_free(item->response_data->error);
    }
    g_free(item->response_data);
  }

  g_free(item);
}

int json_serializer_process_one(json_serializer_t* serializer) {
  if (!serializer) {
    log_error("Invalid JSON serializer pointer");
    return -1;
  }

  response_item_t* item = g_async_queue_try_pop(serializer->queue);
  if (!item) {
    return 0;  // Queue empty - don't log debug message every time
  }

  int result = write_response_to_individual_file(serializer, item);
  if (result == 0) {
    serializer->total_written++;
  } else {
    serializer->total_errors++;
  }

  response_item_free(item);
  return result == 0 ? 1 : -1;
}

cJSON* response_to_json(const struct response* response) {
  if (!response) {
    log_error("Invalid response pointer");
    return NULL;
  }

  cJSON* json = cJSON_CreateObject();
  if (!json) {
    log_error("Failed to create cJSON object");
    return NULL;
  }

  if (response->timestamp) {
    cJSON_AddStringToObject(json, "timestamp", response->timestamp);
  }

  const char* status = response->error ? "FAILURE" : "SUCCESS";
  cJSON_AddStringToObject(json, "status", status);

  if (response->metadata) {
    cJSON* metadata_json = cJSON_CreateObject();

    const char* task_type_str;
    switch (response->metadata->task_type) {
      case STATE:
        task_type_str = "STATE";
        break;
      case EVENT:
        task_type_str = "EVENT";
        break;
      case INTERRUPT:
        task_type_str = "INTERRUPT";
        break;
      default:
        task_type_str = "UNKNOWN";
        break;
    }
    cJSON_AddStringToObject(metadata_json, "task_type", task_type_str);

    // Subtype - fixed to handle each task type correctly
    if (response->metadata->subtype) {
      const char* subtype_str = NULL;

      if (response->metadata->task_type == EVENT) {
        event_task_id_t event_id =
            (event_task_id_t)(uintptr_t)response->metadata->subtype;
        subtype_str = event_task_id_to_str(event_id);
      } else if (response->metadata->task_type == STATE) {
        state_task_id_t state_id =
            (state_task_id_t)(uintptr_t)response->metadata->subtype;
        subtype_str = state_task_id_to_str(state_id);
      } else if (response->metadata->task_type == INTERRUPT) {
        interrupt_task_id_t interrupt_id =
            (interrupt_task_id_t)(uintptr_t)response->metadata->subtype;
        subtype_str = interrupt_task_id_to_str(interrupt_id);
      }

      if (subtype_str) {
        cJSON_AddStringToObject(metadata_json, "subtype", subtype_str);
      } else {
        cJSON_AddStringToObject(metadata_json, "subtype", "UNKNOWN");
      }
    }

    cJSON_AddItemToObject(json, "metadata", metadata_json);
  }

  // Add data (SUCCESS case only)
  if (!response->error && response->data) {
    cJSON* data_json = cJSON_CreateObject();

    // TODO: Add type-specific JSON conversion based on metadata subtype
    // Example:
    if (response->metadata && response->metadata->task_type == EVENT) {
      event_task_id_t event_id =
          (event_task_id_t)(uintptr_t)response->metadata->subtype;
      if (event_id == EVENT_CR0_WRITE) {
        cr0_write_data_t* cr0_data = (cr0_write_data_t*)response->data;
        cJSON* cr0_data_json = cr0_write_data_to_json(cr0_data);
        if (cr0_data_json) {
          cJSON_AddItemToObject(data_json, "cr0_write", cr0_data_json);
        } else {
          cJSON_AddStringToObject(data_json, "_note",
                                  "Failed to convert CR0 data to JSON");
        }
      }
    }

    cJSON_AddItemToObject(json, "data", data_json);
  }

  // Add error (FAILURE case only)
  if (response->error) {
    cJSON* error_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(error_json, "code", response->error->code);
    cJSON_AddStringToObject(error_json, "message", response->error->message);
    cJSON_AddItemToObject(json, "error", error_json);
  }

  return json;
}

int json_serializer_drain_queue(json_serializer_t* serializer) {
  if (!serializer) {
    log_error("Invalid JSON serializer pointer");
    return -1;
  }

  int processed = 0;
  response_item_t* item;

  while ((item = g_async_queue_try_pop(serializer->queue)) != NULL) {
    if (write_response_to_individual_file(serializer, item) == 0) {
      serializer->total_written++;
      processed++;
    } else {
      serializer->total_errors++;
    }
    response_item_free(item);
  }

  return processed;
}