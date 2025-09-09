#include "response.h"
#include <glib-2.0/glib.h>
#include <log.h>
#include <sys/time.h>

/**
 * @brief Create a new metadata object
 * 
 * @param task_type The type of task (STATE, EVENT, or INTERRUPT)
 * @param subtype Pointer to the specific subtype enum (cast to void*)
 * @return Allocated metadata object or NULL on failure
 */
metadata* create_metadata(task_type task_type, void* subtype) {
  metadata* meta = g_malloc0(sizeof(metadata));
  if (!meta) {
    log_error("Failed to allocate memory for metadata");
    return NULL;
  }

  meta->task_type = task_type;
  meta->subtype = subtype;

  return meta;
}

char* generate_timestamp(void) {
  struct timeval time_value;
  struct tm time_structure;
  char* buffer = g_malloc0(32);

  if (buffer == NULL) {
    log_error("Allocation of buffer for timestamp string literal failed");
    return NULL;
  }

  gettimeofday(&time_value, NULL);
  gmtime_r(&time_value.tv_sec, &time_structure);

  if (snprintf(buffer, 32, "%04d-%02d-%02dT%02d:%02d:%02d.%06ld",
               time_structure.tm_year + 1900, time_structure.tm_mon + 1,
               time_structure.tm_mday, time_structure.tm_hour,
               time_structure.tm_min, time_structure.tm_sec,
               time_value.tv_usec) < 0) {
    log_warn("Converting timestamp to strings literal failed.");
  }

  return buffer;
}

error* create_error(int code, const char* message) {
  if (!message) {
    log_error("Cannot create error with NULL message");
    return NULL;
  }

  error* err = g_malloc0(sizeof(error));
  if (!err) {
    log_error("Failed to allocate memory for error object");
    return NULL;
  }

  err->code = code;

  size_t message_len = strlen(message);
  if (message_len >= MESSAGE_LENGTH) {
    strncpy((char*)err->message, message, MESSAGE_LENGTH - 1);
    ((char*)err->message)[MESSAGE_LENGTH - 1] = '\0';
    log_warn("Error message truncated to %d characters", MESSAGE_LENGTH - 1);
  } else {
    strcpy((char*)err->message, message);
  }

  return err;
}

// NOLINTNEXTLINE
struct response* create_success_response(task_type task_type, void* subtype,
                                         void* data_ptr) {
  if (!data_ptr) {
    log_error("Cannot create success response with NULL data");
    return NULL;
  }

  struct response* resp = g_malloc0(sizeof(struct response));
  if (!resp) {
    log_error("Failed to allocate memory for response");
    return NULL;
  }

  resp->timestamp = generate_timestamp();
  if (!resp->timestamp) {
    g_free(resp);
    return NULL;
  }

  resp->metadata = create_metadata(task_type, subtype);
  if (!resp->metadata) {
    free((void*)resp->timestamp);
    g_free(resp);
    return NULL;
  }

  resp->data = data_ptr;
  resp->error = NULL;

  return resp;
}

struct response* create_error_response(task_type task_type, void* subtype,
                                       int error_code,
                                       const char* error_message) {
  if (!error_message) {
    log_error("Cannot create error response with NULL error message");
    return NULL;
  }

  struct response* resp = g_malloc0(sizeof(struct response));
  if (!resp) {
    log_error("Failed to allocate memory for response");
    return NULL;
  }

  resp->timestamp = generate_timestamp();
  if (!resp->timestamp) {
    g_free(resp);
    return NULL;
  }

  resp->metadata = create_metadata(task_type, subtype);
  if (!resp->metadata) {
    free((void*)resp->timestamp);
    g_free(resp);
    return NULL;
  }

  resp->error = create_error(error_code, error_message);
  if (!resp->error) {
    g_free(resp->metadata);
    free((void*)resp->timestamp);
    g_free(resp);
    return NULL;
  }

  resp->data = NULL;

  return resp;
}

/**
 * @brief Free a response object and all its components
 * 
 * @param response Response object to free (can be NULL)
 */
void free_response(struct response* response) {
  if (!response) {
    return;
  }

  if (response->timestamp) {
    free((void*)response->timestamp);
  }

  if (response->metadata) {
    g_free(response->metadata);
  }

  if (response->error) {
    g_free(response->error);
  }

  g_free(response);
}

/**
 * @brief Get error code name as string
 * 
 * @param code Error code
 * @return String representation of error code
 */
const char* error_code_to_string(int code) {
  switch (code) {
    case MEMORY_ALLOCATION_FAILURE:
      return "MEMORY_ALLOCATION_FAILURE";
    case INVALID_ARGUMENTS:
      return "INVALID_ARGUMENTS";
    case VMI_OP_FAILURE:
      return "VMI_OP_FAILURE";
    default:
      return "UNKNOWN_ERROR";
  }
}